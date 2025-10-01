

'use strict';

require('dotenv').config();

const express = require('express');
const admin = require('firebase-admin');
const { body, param, query, validationResult } = require('express-validator');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const morgan = require('morgan');

// ---------- Configuration / Initialization ----------

// Logging setup (winston) for production-grade logs
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [new winston.transports.Console()]
});

// HTTP request logging (morgan) integrated with winston
const stream = {
  write: message => logger.info(message.trim())
};

// Express app
const app = express();
app.use(express.json({ limit: '50kb' })); // limit request size
app.use(helmet()); // security headers
app.use(cors({
  origin: process.env.CORS_ORIGIN || true // tighten this in production
}));
app.use(morgan('combined', { stream }));

// Basic rate-limiting – protect sensitive endpoints from brute force / abuse
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: parseInt(process.env.RATE_LIMIT || '120', 10), // requests per window
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

// Firebase admin init
function initFirebaseAdmin() {
  if (admin.apps.length) return admin.app();

  const projectId = process.env.FIREBASE_PROJECT_ID;
  const serviceAccountPath = process.env.FIREBASE_SERVICE_ACCOUNT_PATH;
  const serviceAccountJSON = process.env.FIREBASE_SERVICE_ACCOUNT;

  let credential;
  if (serviceAccountJSON) {
    credential = admin.credential.cert(JSON.parse(serviceAccountJSON));
  } else if (serviceAccountPath) {
    credential = admin.credential.cert(require(serviceAccountPath));
  } else {
    // Try application default (e.g., when running in GCP)
    credential = admin.credential.applicationDefault();
  }

  admin.initializeApp({
    credential,
    projectId
  });

  return admin.app();
}
initFirebaseAdmin();

const db = admin.firestore();
const FieldValue = admin.firestore.FieldValue;
const ENTITIES = 'entities';

// Constants
const MAX_BATCH_SIZE = 500; // Firestore max batch size
const SERVER_VERSION = '1.0.0';

// ---------- Utility / Helper Functions ----------

/**
 * sanitizeInput - minimal sanitization helper (further validation via express-validator)
 * Note: avoid trying to 'clean' nested structures automatically — validate explicitly.
 */
function sanitizeInput(input) {
  if (typeof input === 'string') {
    return input.trim();
  }
  return input;
}

/**
 * sendError - unified error responder with logging
 */
function sendError(res, status, message, detail) {
  logger.warn({ status, message, detail });
  return res.status(status).json({ error: message });
}

/**
 * authMiddleware - verify Firebase ID token sent in Authorization: Bearer <token>
 * If you want to trust other headers (like from an internal proxy), adapt securely.
 */
async function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const match = authHeader.match(/^Bearer (.*)$/);
  if (!match) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }
  const idToken = match[1];

  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.user = {
      uid: decoded.uid,
      email: decoded.email,
      ...decoded
    };
    return next();
  } catch (err) {
    logger.warn({ msg: 'Invalid auth token', err: err.message });
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

/**
 * generatePath(parentId, entityId, parentPath)
 * - If parentId is null => path = entityId
 * - Else => path = `${parentPath}/${entityId}`
 * parentPath can be passed to avoid extra DB read when available.
 */
async function generatePath(parentId, entityId, parentPath = null) {
  if (!parentId) return entityId;
  if (parentPath !== null) return `${parentPath}/${entityId}`;
  const parentDoc = await db.collection(ENTITIES).doc(parentId).get();
  if (!parentDoc.exists) throw new Error('Parent not found for path generation');
  const parentData = parentDoc.data();
  return `${parentData.path}/${entityId}`;
}

/**
 * getNextPosition(parentId)
 * Finds next available sibling position (max+1). Uses indexing on parentId+position.
 */
async function getNextPosition(parentId) {
  const q = db.collection(ENTITIES)
    .where('parentId', '==', parentId || null)
    .orderBy('position', 'desc')
    .limit(1);

  const snap = await q.get();
  if (snap.empty) return 0;
  const doc = snap.docs[0].data();
  return (doc.position || 0) + 1;
}

/**
 * checkCircularReference(entityId, newParentId)
 * Prevent entity from becoming its own ancestor (directly or indirectly)
 */
async function checkCircularReference(entityId, newParentId) {
  if (!newParentId) return false;
  if (entityId === newParentId) return true;
  const parentDoc = await db.collection(ENTITIES).doc(newParentId).get();
  if (!parentDoc.exists) return false;
  const parentData = parentDoc.data();
  // If parent's path contains the entityId then it's circular
  const ancestorPath = parentData.path || '';
  return ancestorPath.split('/').includes(entityId);
}

/**
 * updateAncestorMetricsIncrement(parentId, directDelta, descendantDelta)
 * Walk up the ancestor chain updating metrics (incremental) – uses transactions per ancestor.
 * For deep trees this will iterate; depth is expected to be reasonable. We avoid a single huge transaction
 * because Firestore transaction size/timeouts can be a problem.
 */
async function updateAncestorMetricsIncrement(parentId, directDelta = 0, descendantDelta = 0) {
  let curParentId = parentId;
  const ops = [];
  // loop safety: limit to 100 levels (very deep trees are unusual)
  for (let depth = 0; curParentId && depth < 100; depth++) {
    const parentRef = db.collection(ENTITIES).doc(curParentId);
    try {
      await db.runTransaction(async (tx) => {
        const snapshot = await tx.get(parentRef);
        if (!snapshot.exists) {
          curParentId = null;
          return;
        }
        const data = snapshot.data();
        const metrics = data.metrics || { descendantCount: 0, directChildrenCount: 0 };
        const newMetrics = {
          descendantCount: Math.max(0, (metrics.descendantCount || 0) + descendantDelta),
          directChildrenCount: Math.max(0, (metrics.directChildrenCount || 0) + directDelta)
        };
        tx.update(parentRef, { metrics: newMetrics, updatedAt: FieldValue.serverTimestamp() });
      });
    } catch (err) {
      logger.error({ msg: 'Failed updating ancestor metrics', parentId: curParentId, err: err.message });
      throw err;
    }
    // get next ancestor
    const next = await db.collection(ENTITIES).doc(curParentId).get();
    if (!next.exists) break;
    const nextData = next.data();
    curParentId = nextData.parentId || null;
  }
}

/**
 * batchUpdateDescendants(oldPathPrefix, newPathPrefix, updates)
 * Find descendants where path starts with oldPathPrefix + '/' and update each path and other fields
 * Uses lexical range queries to emulate startsWith.
 */
async function batchUpdateDescendants(oldPathPrefix, newPathPrefix) {
  // Firestore range trick: startAt oldPrefix + '/' and endBefore oldPrefix + '/\uf8ff'
  const start = oldPathPrefix + '/';
  const end = oldPathPrefix + '/\uf8ff';
  let lastDoc = null;
  const updated = [];

  while (true) {
    let q = db.collection(ENTITIES)
      .where('path', '>=', start)
      .where('path', '<=', end)
      .orderBy('path')
      .limit(MAX_BATCH_SIZE);

    if (lastDoc) q = q.startAfter(lastDoc);

    const snap = await q.get();
    if (snap.empty) break;

    const batch = db.batch();
    snap.docs.forEach(doc => {
      const data = doc.data();
      // derive new path by replacing prefix
      const newPath = data.path.replace(`${oldPathPrefix}/`, `${newPathPrefix}/`);
      // compute new depth
      const newDepth = newPath.split('/').length - 1;
      batch.update(doc.ref, {
        path: newPath,
        depth: newDepth,
        updatedAt: FieldValue.serverTimestamp()
      });
      updated.push({ id: doc.id, oldPath: data.path, newPath });
    });

    await batch.commit();
    lastDoc = snap.docs[snap.docs.length - 1];
    // if fewer than batch size then we're done
    if (snap.size < MAX_BATCH_SIZE) break;
  }
  return updated;
}

/**
 * updateDescendantPaths(entityId, oldPath, newPath)
 * Update all descendant docs paths and depths after entity is moved/renamed.
 */
async function updateDescendantPaths(entityId, oldPath, newPath) {
  // oldPath is path before change, newPath is path after change
  // Update the immediate entity separately (caller should update entity).
  return await batchUpdateDescendants(oldPath, newPath);
}

/**
 * computeDescendantCount(entityId)
 * Only used for repair/verification - expensive for big trees.
 * Returns counts and optionally writes them back (not used automatically).
 */
async function computeDescendantCount(entityId) {
  const entityRef = db.collection(ENTITIES).doc(entityId);
  const entitySnap = await entityRef.get();
  if (!entitySnap.exists) throw new Error('Entity not found in computeDescendantCount');
  const path = entitySnap.data().path;
  const start = path + '/';
  const end = path + '/\uf8ff';
  // Pagination to count
  let lastDoc = null;
  let total = 0;
  while (true) {
    let q = db.collection(ENTITIES)
      .where('path', '>=', start)
      .where('path', '<=', end)
      .orderBy('path')
      .limit(MAX_BATCH_SIZE);
    if (lastDoc) q = q.startAfter(lastDoc);
    const snap = await q.get();
    if (snap.empty) break;
    total += snap.size;
    lastDoc = snap.docs[snap.docs.length - 1];
    if (snap.size < MAX_BATCH_SIZE) break;
  }
  return total;
}

/**
 * ensureUniqueSiblingPosition(parentId, position)
 * If the requested position collides with existing siblings, shift subsequent siblings' positions to make room.
 * We keep the number of writes bounded by shifting only siblings with position >= requested position.
 */
async function ensureUniqueSiblingPosition(parentId, requestedPosition) {
  const siblingsQuery = db.collection(ENTITIES)
    .where('parentId', '==', parentId || null)
    .where('position', '>=', requestedPosition)
    .orderBy('position');

  const snapshots = await siblingsQuery.get();
  if (snapshots.empty) return;
  const batch = db.batch();
  let count = 0;
  snapshots.docs.forEach(doc => {
    // increment position by 1
    const newPos = (doc.data().position || 0) + 1;
    batch.update(doc.ref, { position: newPos, updatedAt: FieldValue.serverTimestamp() });
    count++;
    if (count >= MAX_BATCH_SIZE - 1) {
      // commit chunk and continue (avoid exceeding batch limit)
      batch.commit();
    }
  });
  await batch.commit();
}

// ---------- Input validation middlewares ----------

const validateEntityCreate = [
  body('name').isString().isLength({ min: 1, max: 200 }).trim(),
  body('email').optional().isEmail().normalizeEmail(),
  body('role').isString().isIn(['supreme', 'leader_agent', 'client']).withMessage('Invalid role'),
  body('parentId').optional().isString().trim(),
  async (req, res, next) => {
    // check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    // sanitize
    req.body.name = sanitizeInput(req.body.name);
    req.body.email = req.body.email ? sanitizeInput(req.body.email) : null;
    next();
  }
];

const validateEntityIdParam = [
  param('id').isString().isLength({ min: 1 }),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    next();
  }
];

// ---------- API Endpoints ----------

// Ping
app.get('/ping', (req, res) => res.json({ pong: true }));

// Uptime & server info
app.get('/uptime', (req, res) => {
  const mem = process.memoryUsage();
  res.json({
    status: 'ok',
    uptimeSec: process.uptime(),
    memory: {
      rss: mem.rss,
      heapTotal: mem.heapTotal,
      heapUsed: mem.heapUsed
    },
    version: SERVER_VERSION,
    platform: process.platform,
    nodeVersion: process.version
  });
});

// DB health check
app.get('/health/db', async (req, res) => {
  try {
    // quick Firestore action
    await db.collection('_health_check_').doc('ping').set({ ts: FieldValue.serverTimestamp() });
    return res.json({ status: 'ok', firestore: true });
  } catch (err) {
    logger.error({ msg: 'Firestore health check failed', err: err.message });
    return res.status(500).json({ status: 'error', firestore: false, message: err.message });
  }
});

// ---------- Entities CRUD ----------

/**
 * POST /entities
 * Create new entity.
 * Body: { id? (optional override), name, email?, role, parentId? , customFields? }
 *
 * Auto-generates id if not provided; but recommended to use Firebase Auth UID as id.
 */
app.post('/entities', authMiddleware, validateEntityCreate, async (req, res) => {
  try {
    // Limit which roles can create top-level 'supreme' etc based on authorization rules (example)
    const creator = req.user;
    // Authorization example: only 'supreme' in DB or admin can create top-level. This is a placeholder.
    // Implement real RBAC depending on your app's needs.
    const { id: overrideId, name, email, role, parentId = null, customFields = {} } = req.body;

    // if parentId provided, ensure it exists
    let parentSnap = null;
    let parentPath = null;
    if (parentId) {
      parentSnap = await db.collection(ENTITIES).doc(parentId).get();
      if (!parentSnap.exists) return sendError(res, 400, 'parentId does not exist');
      parentPath = parentSnap.data().path;
    }

    const newId = overrideId || db.collection(ENTITIES).doc().id; // generate id if not provided
    const position = await getNextPosition(parentId);
    // ensure position uniqueness among siblings (shifts others if required)
    await ensureUniqueSiblingPosition(parentId, position);

    const path = await generatePath(parentId, newId, parentPath);
    const depth = path.split('/').length - 1;
    const now = FieldValue.serverTimestamp();

    const docRef = db.collection(ENTITIES).doc(newId);
    const docData = {
      id: newId,
      name,
      email: email || null,
      role,
      parentId: parentId || null,
      position,
      path,
      depth,
      status: 'active',
      createdAt: now,
      updatedAt: now,
      history: {
        roleChanges: [],
        hierarchyChanges: []
      },
      metrics: {
        descendantCount: 0,
        directChildrenCount: 0
      },
      customFields: customFields || {}
    };

    // write entity
    await docRef.set(docData);

    // update ancestor metrics: increment direct child count on immediate parent, and descendant counts up the chain
    if (parentId) {
      // immediate parent: directChildrenCount += 1, descendantCount += 1
      await updateAncestorMetricsIncrement(parentId, 1, 1);
    }

    logger.info({ msg: 'Entity created', id: newId, createdBy: creator.uid });
    const out = (await docRef.get()).data();
    return res.status(201).json(out);
  } catch (err) {
    logger.error({ msg: 'Failed creating entity', err: err.message, stack: err.stack });
    return sendError(res, 500, 'Failed creating entity', err.message);
  }
});

/**
 * GET /entities
 * Query params:
 *  - parentId? : list children of parent
 *  - role? : filter by role
 *  - limit?, pageToken? (pagination using offset simple approach)
 *
 * Returns ordered by position
 */
app.get('/entities', authMiddleware, [
  query('parentId').optional().isString(),
  query('role').optional().isString(),
  query('limit').optional().isInt({ min: 1, max: 200 }).toInt()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { parentId, role } = req.query;
    const limit = parseInt(req.query.limit || '100', 10);

    let q = db.collection(ENTITIES);
    if (parentId !== undefined) q = q.where('parentId', '==', parentId || null);
    if (role) q = q.where('role', '==', role);
    q = q.orderBy('position', 'asc').limit(limit);

    const snap = await q.get();
    const items = snap.docs.map(d => d.data());
    return res.json({ items });
  } catch (err) {
    logger.error({ msg: 'Failed listing entities', err: err.message });
    return sendError(res, 500, 'Failed listing entities', err.message);
  }
});

/**
 * GET /entities/:id
 */
app.get('/entities/:id', authMiddleware, validateEntityIdParam, async (req, res) => {
  try {
    const doc = await db.collection(ENTITIES).doc(req.params.id).get();
    if (!doc.exists) return sendError(res, 404, 'Entity not found');
    return res.json(doc.data());
  } catch (err) {
    logger.error({ msg: 'Failed getting entity', id: req.params.id, err: err.message });
    return sendError(res, 500, 'Failed getting entity', err.message);
  }
});

/**
 * PUT /entities/:id
 * Updatable: name, email, role, status, customFields
 * Tracks role changes in history.
 */
app.put('/entities/:id', authMiddleware, [
  param('id').isString(),
  body('name').optional().isString().isLength({ min: 1, max: 200 }).trim(),
  body('email').optional().isEmail().normalizeEmail(),
  body('role').optional().isString().isIn(['supreme', 'leader_agent', 'client']),
  body('status').optional().isString().isIn(['active', 'inactive']),
  body('customFields').optional().isObject()
], async (req, res) => {
  try {
    const id = req.params.id;
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const docRef = db.collection(ENTITIES).doc(id);
    const snap = await docRef.get();
    if (!snap.exists) return sendError(res, 404, 'Entity not found');

    const current = snap.data();
    const updates = {};
    const now = FieldValue.serverTimestamp();

    if (req.body.name) updates.name = sanitizeInput(req.body.name);
    if (req.body.email !== undefined) updates.email = req.body.email ? sanitizeInput(req.body.email) : null;
    if (req.body.status) updates.status = req.body.status;
    if (req.body.customFields) updates.customFields = req.body.customFields;

    // handle role change and history
    if (req.body.role && req.body.role !== current.role) {
      const roleChange = {
        fromRole: current.role,
        toRole: req.body.role,
        changedAt: now,
        changedBy: req.user.uid
      };
      const history = current.history || { roleChanges: [], hierarchyChanges: [] };
      history.roleChanges = history.roleChanges || [];
      history.roleChanges.push(roleChange);
      updates.history = history;
      updates.role = req.body.role;
    }

    if (Object.keys(updates).length === 0) return res.status(400).json({ error: 'No updatable fields provided' });

    updates.updatedAt = now;
    await docRef.update(updates);

    logger.info({ msg: 'Entity updated', id, updatedBy: req.user.uid, updates });
    const updated = (await docRef.get()).data();
    return res.json(updated);
  } catch (err) {
    logger.error({ msg: 'Failed updating entity', err: err.message });
    return sendError(res, 500, 'Failed updating entity', err.message);
  }
});

/**
 * DELETE /entities/:id
 * Only allowed if entity has no direct children.
 */
app.delete('/entities/:id', authMiddleware, validateEntityIdParam, async (req, res) => {
  try {
    const id = req.params.id;
    const docRef = db.collection(ENTITIES).doc(id);
    const snap = await docRef.get();
    if (!snap.exists) return sendError(res, 404, 'Entity not found');

    const entity = snap.data();

    // ensure no children
    const childrenSnap = await db.collection(ENTITIES)
      .where('parentId', '==', id)
      .limit(1)
      .get();
    if (!childrenSnap.empty) {
      return sendError(res, 409, 'Cannot delete entity with children');
    }

    // delete entity
    await docRef.delete();

    // update ancestor metrics: decrement directChildrenCount on parent and descendant counts up the chain
    if (entity.parentId) {
      await updateAncestorMetricsIncrement(entity.parentId, -1, -1);
    }

    logger.info({ msg: 'Entity deleted', id, deletedBy: req.user.uid });
    return res.json({ id });
  } catch (err) {
    logger.error({ msg: 'Failed deleting entity', err: err.message });
    return sendError(res, 500, 'Failed deleting entity', err.message);
  }
});

// ---------- Hierarchy Operations ----------

/**
 * PUT /entities/:id/move
 * Body: { newParentId? }
 * - Validates new parent
 * - Prevents circular references
 * - Updates entity's parentId, path, depth, position
 * - Recursively updates descendants' paths
 * - Updates metrics for old and new parents
 * - Tracks hierarchy change in history
 */
app.put('/entities/:id/move', authMiddleware, [
  param('id').isString(),
  body('newParentId').optional().isString()
], async (req, res) => {
  try {
    const id = req.params.id;
    const newParentId = req.body.newParentId || null;

    // load entity
    const docRef = db.collection(ENTITIES).doc(id);
    const docSnap = await docRef.get();
    if (!docSnap.exists) return sendError(res, 404, 'Entity not found');
    const entity = docSnap.data();

    // if newParentId equals current parent => no-op
    if ((entity.parentId || null) === (newParentId || null)) {
      return res.status(200).json({ msg: 'Already under requested parent', entity });
    }

    // if newParentId provided, ensure exists
    let newParentSnap = null;
    let newParentPath = null;
    if (newParentId) {
      newParentSnap = await db.collection(ENTITIES).doc(newParentId).get();
      if (!newParentSnap.exists) return sendError(res, 400, 'newParentId does not exist');
      newParentPath = newParentSnap.data().path;
    }

    // prevent circular reference
    const circular = await checkCircularReference(id, newParentId);
    if (circular) return sendError(res, 400, 'Invalid move: circular reference detected');

    // Calculate new position among siblings
    const newPosition = await getNextPosition(newParentId);

    // Ensure unique positions (shift siblings if needed)
    await ensureUniqueSiblingPosition(newParentId, newPosition);

    // compute new path and depth
    const oldPath = entity.path;
    const newPath = await generatePath(newParentId, id, newParentPath);
    const newDepth = newPath.split('/').length - 1;

    // start main transaction to update entity and write history
    await db.runTransaction(async (tx) => {
      const doc = await tx.get(docRef);
      if (!doc.exists) throw new Error('Entity disappeared during move');
      const cur = doc.data();
      // build hierarchy change entry
      const hierarchyChange = {
        fromParentId: cur.parentId || null,
        toParentId: newParentId || null,
        fromPosition: cur.position || 0,
        toPosition: newPosition,
        changedAt: FieldValue.serverTimestamp(),
        changedBy: req.user.uid
      };
      const history = cur.history || { roleChanges: [], hierarchyChanges: [] };
      history.hierarchyChanges = history.hierarchyChanges || [];
      history.hierarchyChanges.push(hierarchyChange);

      tx.update(docRef, {
        parentId: newParentId || null,
        position: newPosition,
        path: newPath,
        depth: newDepth,
        history,
        updatedAt: FieldValue.serverTimestamp()
      });
    });

    // update descendants' paths (outside transaction; may be expensive)
    const updatedDescendants = await updateDescendantPaths(id, oldPath, newPath);

    // update ancestor metrics: decrement for old parent chain, increment for new parent chain
    if (entity.parentId) {
      // The entity itself and all its descendants moved, so descendantDelta = -(1 + descendantCount)
      const totalMoved = 1 + (entity.metrics ? (entity.metrics.descendantCount || 0) : 0);
      await updateAncestorMetricsIncrement(entity.parentId, -1, -totalMoved);
    }
    if (newParentId) {
      const totalMoved = 1 + (entity.metrics ? (entity.metrics.descendantCount || 0) : 0);
      await updateAncestorMetricsIncrement(newParentId, 1, totalMoved);
    }

    // log & return
    const updatedEntity = (await db.collection(ENTITIES).doc(id).get()).data();
    logger.info({
      msg: 'Entity moved',
      id,
      from: oldPath,
      to: newPath,
      updatedBy: req.user.uid,
      descendantUpdates: updatedDescendants.length
    });

    return res.json({ entity: updatedEntity, updatedDescendantsCount: updatedDescendants.length });
  } catch (err) {
    logger.error({ msg: 'Failed moving entity', err: err.message, stack: err.stack });
    return sendError(res, 500, 'Failed moving entity', err.message);
  }
});

/**
 * GET /entities/:id/hierarchy
 * Return entity and all descendants (path-based query).
 * Supports ?limit to page large trees.
 */
app.get('/entities/:id/hierarchy', authMiddleware, [
  param('id').isString(),
  query('limit').optional().isInt({ min: 1, max: 1000 }).toInt()
], async (req, res) => {
  try {
    const id = req.params.id;
    const limit = parseInt(req.query.limit || '1000', 10);
    const rootSnap = await db.collection(ENTITIES).doc(id).get();
    if (!rootSnap.exists) return sendError(res, 404, 'Entity not found');

    const root = rootSnap.data();
    const path = root.path;
    const start = path + '/';
    const end = path + '/\uf8ff';

    // fetch root + descendants
    const items = [root];
    let lastDoc = null;
    let fetched = 0;
    while (fetched < limit) {
      let q = db.collection(ENTITIES)
        .where('path', '>=', start)
        .where('path', '<=', end)
        .orderBy('path')
        .limit(Math.min(MAX_BATCH_SIZE, limit - fetched));
      if (lastDoc) q = q.startAfter(lastDoc);
      const snap = await q.get();
      if (snap.empty) break;
      snap.docs.forEach(d => items.push(d.data()));
      fetched += snap.size;
      lastDoc = snap.docs[snap.docs.length - 1];
      if (snap.size < MAX_BATCH_SIZE) break;
    }

    return res.json({ root, descendants: items.slice(1) });
  } catch (err) {
    logger.error({ msg: 'Failed fetching hierarchy', err: err.message });
    return sendError(res, 500, 'Failed fetching hierarchy', err.message);
  }
});

// ---------- Error handling middleware & 404 ----------

// 404
app.use((req, res) => {
  return res.status(404).json({ error: 'Not found' });
});

// Centralized error handler (should not leak internal errors in production)
app.use((err, req, res, next) => {
  logger.error({ msg: 'Unhandled error', err: err && err.message, stack: err && err.stack });
  if (process.env.NODE_ENV === 'production') {
    res.status(500).json({ error: 'Internal server error' });
  } else {
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ---------- Server start ----------

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  logger.info({ msg: `Server listening`, port: PORT, env: process.env.NODE_ENV || 'development' });
});
