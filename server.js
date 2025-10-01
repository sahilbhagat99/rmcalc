/**
 * @fileoverview Main server file for the Hierarchical Entity Management System.
 * @description This file initializes an Express server, connects to Firebase Firestore,
 * and exposes a RESTful API for managing a tree-structured entity system. It handles
 * CRUD operations, hierarchy management (moving nodes), metric calculations
 * (descendant/children counts), and history tracking.
 *
 * @version 2.0.0
 * @author Your Name
 * @license MIT
 */

// -----------------------------------------------------------------------------
// 1. IMPORTS AND INITIALIZATION
// -----------------------------------------------------------------------------
const express = require('express');
const admin = require('firebase-admin');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const cluster = require('cluster');
const os = require('os');
const rateLimit = require('express-rate-limit');

// Use environment variables for configuration
if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}

const numCPUs = os.cpus().length;

// --- Firebase Admin SDK Initialization ---
// IMPORTANT: In a production environment (like Render), store your service account key
// as a secret environment variable.
// 1. Go to Render Dashboard -> Your Service -> Environment.
// 2. Add a new Secret File.
// 3. Set the filepath to './serviceAccountKey.json'.
// 4. Paste the contents of your JSON key file as the value.
try {
  if (process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON) {
     const serviceAccount = JSON.parse(process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON);
     admin.initializeApp({
       credential: admin.credential.cert(serviceAccount)
     });
  } else {
    const serviceAccount = require('./serviceAccountKey.json');
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
  }
} catch (error) {
  console.error('Error initializing Firebase Admin SDK. Make sure serviceAccountKey.json is present.');
  console.error('For production, set this as a secret environment variable.');
  // In a real app, you might fall back to GOOGLE_APPLICATION_CREDENTIALS env var
  // process.exit(1); // Uncomment to exit if Firebase connection fails
}

const db = admin.firestore();
const entitiesCollection = db.collection('entities');
const FieldValue = admin.firestore.FieldValue;

// --- Express App Initialization ---
const app = express();
const PORT = process.env.PORT || 3000;

// -----------------------------------------------------------------------------
// 2. MIDDLEWARE
// -----------------------------------------------------------------------------
app.use(helmet()); // Sets various HTTP headers for security

// --- CORS Configuration ---
const whitelist = process.env.CORS_WHITELIST ? process.env.CORS_WHITELIST.split(',') : [];
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin || whitelist.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  }
};
// Use production-ready CORS settings if in production
app.use(process.env.NODE_ENV === 'production' ? cors(corsOptions) : cors());

app.use(express.json()); // Parses incoming JSON requests

// --- Logging ---
// Use 'combined' format for production logging, and 'dev' for development
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

// --- Rate Limiting ---
const apiLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 100, // Limit each IP to 100 requests per windowMs
	standardHeaders: true,
	legacyHeaders: false,
  message: 'Too many requests from this IP, please try again after 15 minutes'
});


/**
 * Authentication Middleware (Production Ready)
 * @description Verifies Firebase Auth ID token from the Authorization header.
 * Attaches the decoded user payload to `req.user`.
 */
const authenticate = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: No token provided.' });
  }

  const idToken = authHeader.split('Bearer ')[1];
  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error('Error verifying auth token:', error);
    return res.status(403).json({ error: 'Forbidden: Invalid or expired token.' });
  }
};


// -----------------------------------------------------------------------------
// 3. HELPER FUNCTIONS
// -----------------------------------------------------------------------------

/**
 * Retrieves the next available position for a new entity under a given parent.
 * @param {string|null} parentId - The ID of the parent entity, or null for root.
 * @returns {Promise<number>} The next integer position.
 */
const getNextPosition = async (parentId) => {
  const query = entitiesCollection.where('parentId', '==', parentId).orderBy('position', 'desc').limit(1);
  const snapshot = await query.get();
  if (snapshot.empty) {
    return 0; // First child
  }
  return snapshot.docs[0].data().position + 1;
};

/**
 * Generates the hierarchical path for an entity.
 * @param {string|null} parentId - The ID of the parent entity.
 * @param {string} entityId - The ID of the current entity.
 * @returns {Promise<string>} The full hierarchical path.
 */
const generatePath = async (parentId, entityId) => {
  if (!parentId) {
    return entityId;
  }
  const parentDoc = await entitiesCollection.doc(parentId).get();
  if (!parentDoc.exists) {
    throw new Error('Parent entity not found.');
  }
  const parentPath = parentDoc.data().path;
  return `${parentPath}/${entityId}`;
};

/**
 * Updates descendant and direct children counts for all ancestors of an entity.
 * Uses Firestore transactions for atomicity.
 * @param {FirebaseFirestore.Transaction} transaction - The Firestore transaction object.
 * @param {string|null} parentId - The starting parent ID.
 * @param {number} descendantChange - The value to increment/decrement descendantCount by.
 * @param {number} directChildrenChange - The value to increment/decrement directChildrenCount by for the immediate parent.
 */
const updateAncestorMetrics = async (transaction, parentId, descendantChange, directChildrenChange) => {
  if (!parentId) return;

  const parentRef = entitiesCollection.doc(parentId);
  const parentDoc = await transaction.get(parentRef);
  if (!parentDoc.exists) {
    console.warn(`Attempted to update metrics for non-existent parent: ${parentId}`);
    return;
  }

  // Update direct parent's directChildrenCount
  transaction.update(parentRef, {
    'metrics.descendantCount': FieldValue.increment(descendantChange),
    'metrics.directChildrenCount': FieldValue.increment(directChildrenChange),
  });

  // Update all other ancestors' descendantCount
  const parentData = parentDoc.data();
  const ancestorIds = parentData.path.split('/');
  
  // The last part of the path is the parent itself, which we already updated.
  // So we iterate through the "grandparents" and up.
  if (ancestorIds.length > 1) {
    for (let i = 0; i < ancestorIds.length - 1; i++) {
      const ancestorId = ancestorIds[i];
      const ancestorRef = entitiesCollection.doc(ancestorId);
      transaction.update(ancestorRef, { 'metrics.descendantCount': FieldValue.increment(descendantChange) });
    }
  }
};


// -----------------------------------------------------------------------------
// 4. API ROUTES
// -----------------------------------------------------------------------------

const router = express.Router();

// --- Entity Operations ---

/**
 * POST /entities
 * @description Creates a new entity.
 */
router.post('/entities', authenticate, async (req, res, next) => {
  const { name, email, role, parentId = null, customFields = {} } = req.body;
  const changedBy = req.user.uid;

  if (!name || !email || !role) {
    return res.status(400).json({ error: 'Missing required fields: name, email, role.' });
  }

  try {
    const newEntityRef = entitiesCollection.doc();
    const newEntityId = newEntityRef.id;

    await db.runTransaction(async (transaction) => {
      const position = await getNextPosition(parentId);
      const path = await generatePath(parentId, newEntityId);
      const depth = parentId ? path.split('/').length -1 : 0;
      
      const newEntity = {
        id: newEntityId,
        name,
        email,
        role,
        parentId,
        position,
        path,
        depth,
        status: 'active',
        createdAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
        history: {
          roleChanges: [],
          hierarchyChanges: []
        },
        metrics: {
          descendantCount: 0,
          directChildrenCount: 0,
        },
        customFields
      };

      transaction.set(newEntityRef, newEntity);
      
      // Update metrics for all ancestors
      if (parentId) {
        await updateAncestorMetrics(transaction, parentId, 1, 1);
      }
    });

    const createdEntity = await newEntityRef.get();
    res.status(201).json(createdEntity.data());

  } catch (error) {
    next(error);
  }
});


/**
 * GET /entities
 * @description Lists entities with optional filtering and pagination.
 * @query {string} [parentId=null] - Filter by parent ID. Use 'null' for root entities.
 * @query {string} [role] - Filter by entity role.
 * @query {number} [limit=10] - Number of entities to return.
 * @query {string} [startAfter] - The ID of the entity to start after for pagination.
 */
router.get('/entities', async (req, res, next) => {
  try {
    let query = entitiesCollection;
    const { parentId, role, limit = 10, startAfter } = req.query;
    
    // Firestore requires that the first orderBy field is the same as the where field
    // if you use inequality filters. Since we are ordering by position, we'll filter in code for parentId.
    // For optimal performance, ensure you have a composite index on (role, position) if you filter by role.
    if (parentId === 'null') {
      query = query.where('parentId', '==', null);
    } else if (parentId) {
      query = query.where('parentId', '==', parentId);
    }

    if (role) {
      query = query.where('role', '==', role);
    }
    
    query = query.orderBy('position').limit(Number(limit));

    if (startAfter) {
      const lastVisibleDoc = await entitiesCollection.doc(startAfter).get();
      if(lastVisibleDoc.exists) {
        query = query.startAfter(lastVisibleDoc);
      }
    }
    
    const snapshot = await query.get();
    const entities = snapshot.docs.map(doc => doc.data());
    
    // Determine the cursor for the next page
    const lastDoc = snapshot.docs[snapshot.docs.length - 1];
    const nextCursor = lastDoc ? lastDoc.id : null;

    res.status(200).json({ 
      entities,
      nextCursor 
    });
  } catch (error) {
    next(error);
  }
});


/**
 * GET /entities/:id
 * @description Gets a single entity by its ID.
 */
router.get('/entities/:id', async (req, res, next) => {
  try {
    const doc = await entitiesCollection.doc(req.params.id).get();
    if (!doc.exists) {
      return res.status(404).json({ error: 'Entity not found.' });
    }
    res.status(200).json(doc.data());
  } catch (error) {
    next(error);
  }
});

/**
 * PUT /entities/:id
 * @description Updates an existing entity's details.
 */
router.put('/entities/:id', authenticate, async (req, res, next) => {
  const { id } = req.params;
  const { name, email, role, status, customFields } = req.body;
  const changedBy = req.user.uid;

  try {
    const entityRef = entitiesCollection.doc(id);
    const doc = await entityRef.get();

    if (!doc.exists) {
      return res.status(404).json({ error: 'Entity not found.' });
    }

    const currentData = doc.data();
    const updatePayload = { updatedAt: FieldValue.serverTimestamp() };
    
    if (name) updatePayload.name = name;
    if (email) updatePayload.email = email;
    if (status) updatePayload.status = status;
    if (customFields) updatePayload.customFields = customFields;
    
    // Handle role change history
    if (role && role !== currentData.role) {
      updatePayload.role = role;
      updatePayload['history.roleChanges'] = FieldValue.arrayUnion({
        fromRole: currentData.role,
        toRole: role,
        changedAt: new Date(),
        changedBy
      });
    }

    await entityRef.update(updatePayload);
    const updatedDoc = await entityRef.get();
    res.status(200).json(updatedDoc.data());

  } catch (error) {
    next(error);
  }
});


/**
 * DELETE /entities/:id
 * @description Deletes an entity if it has no children.
 */
router.delete('/entities/:id', authenticate, async (req, res, next) => {
  const { id } = req.params;

  try {
    await db.runTransaction(async (transaction) => {
      const entityRef = entitiesCollection.doc(id);
      const doc = await transaction.get(entityRef);

      if (!doc.exists) {
        throw { status: 404, message: 'Entity not found.' };
      }
      
      const entityData = doc.data();
      if (entityData.metrics.directChildrenCount > 0) {
        throw { status: 400, message: 'Cannot delete an entity with children. Reassign children first.' };
      }

      // Decrement ancestor metrics
      if (entityData.parentId) {
        await updateAncestorMetrics(transaction, entityData.parentId, -1, -1);
      }
      
      transaction.delete(entityRef);
    });
    
    res.status(204).send();

  } catch (error) {
    if (error.status) {
      return res.status(error.status).json({ error: error.message });
    }
    next(error);
  }
});


// --- Hierarchy Operations ---

/**
 * PUT /entities/:id/move
 * @description Moves an entity to a new parent.
 */
router.put('/entities/:id/move', authenticate, async (req, res, next) => {
    const { id } = req.params;
    const { newParentId = null } = req.body;
    const changedBy = req.user.uid;

    if (id === newParentId) {
        return res.status(400).json({ error: "An entity cannot be its own parent." });
    }

    try {
        await db.runTransaction(async (transaction) => {
            const entityRef = entitiesCollection.doc(id);
            const entityDoc = await transaction.get(entityRef);

            if (!entityDoc.exists) {
                throw { status: 404, message: "Entity to move not found." };
            }

            const entityData = entityDoc.data();
            const oldParentId = entityData.parentId;
            const oldPath = entityData.path;
            const totalMovedCount = entityData.metrics.descendantCount + 1;

            if (oldParentId === newParentId) {
              throw { status: 400, message: "Entity is already under the specified parent." };
            }
            
            // --- Circular Reference Check & New Parent Validation ---
            let newParentData = null;
            let newParentPath = '';
            if (newParentId) {
                const newParentRef = entitiesCollection.doc(newParentId);
                const newParentDoc = await transaction.get(newParentRef);
                if (!newParentDoc.exists) {
                    throw { status: 404, message: "New parent entity not found." };
                }
                newParentData = newParentDoc.data();
                newParentPath = newParentData.path;
                
                // An entity cannot be moved under one of its own descendants.
                if (newParentPath.startsWith(oldPath)) {
                    throw { status: 400, message: "Circular reference detected: Cannot move an entity under its own descendant." };
                }
            }

            // --- Update Metrics ---
            // 1. Decrement old ancestors
            if (oldParentId) {
                await updateAncestorMetrics(transaction, oldParentId, -totalMovedCount, -1);
            }
            // 2. Increment new ancestors
            if (newParentId) {
                await updateAncestorMetrics(transaction, newParentId, totalMovedCount, 1);
            }
            
            // --- Prepare Entity and Descendants for Update ---
            const batch = db.batch();

            // 1. Update the moved entity itself
            const newPosition = await getNextPosition(newParentId);
            const newPath = newParentId ? `${newParentPath}/${id}` : id;
            const newDepth = newParentId ? newParentData.depth + 1 : 0;
            const depthChange = newDepth - entityData.depth;
            
            transaction.update(entityRef, {
                parentId: newParentId,
                position: newPosition,
                path: newPath,
                depth: newDepth,
                updatedAt: FieldValue.serverTimestamp(),
                'history.hierarchyChanges': FieldValue.arrayUnion({
                    fromParentId: oldParentId,
                    toParentId: newParentId,
                    fromPosition: entityData.position,
                    toPosition: newPosition,
                    changedAt: new Date(),
                    changedBy
                })
            });

            // 2. Recursively update all descendants
            const descendantsQuery = entitiesCollection.where('path', '>=', oldPath + '/').where('path', '<', oldPath + '0');
            const descendantsSnapshot = await transaction.get(descendantsQuery);
            
            descendantsSnapshot.docs.forEach(doc => {
                const descendantData = doc.data();
                const updatedPath = descendantData.path.replace(oldPath, newPath);
                transaction.update(doc.ref, {
                    path: updatedPath,
                    depth: descendantData.depth + depthChange
                });
            });
        });

        const updatedDoc = await entitiesCollection.doc(id).get();
        res.status(200).json(updatedDoc.data());

    } catch (error) {
        if (error.status) {
            return res.status(error.status).json({ error: error.message });
        }
        next(error);
    }
});


/**
 * GET /entities/:id/hierarchy
 * @description Gets an entity and its entire subtree of descendants.
 */
router.get('/entities/:id/hierarchy', async (req, res, next) => {
  try {
    const { id } = req.params;
    const rootDoc = await entitiesCollection.doc(id).get();
    
    if (!rootDoc.exists) {
      return res.status(404).json({ error: 'Entity not found.' });
    }

    const rootEntity = rootDoc.data();
    const path = rootEntity.path;

    // Query for all documents where the path starts with the root's path + '/'
    // The second where clause with a character just after '/' helps to correctly bound the query.
    const descendantsQuery = entitiesCollection.where('path', '>=', path + '/').where('path', '<', path + '0');
    const descendantsSnapshot = await descendantsQuery.get();
    
    const descendants = descendantsSnapshot.docs.map(doc => doc.data());

    res.status(200).json({
      entity: rootEntity,
      descendants: descendants
    });

  } catch (error) {
    next(error);
  }
});


// -----------------------------------------------------------------------------
// 5. MONITORING AND HEALTH CHECKS
// -----------------------------------------------------------------------------

/**
 * GET /ping
 * @description A simple ping endpoint to check if the server is responsive.
 */
router.get('/ping', (req, res) => {
  res.status(200).send('pong');
});

/**
 * GET /uptime
 * @description Provides server health and process information.
 */
router.get('/uptime', (req, res) => {
  res.status(200).json({
    status: 'ok',
    uptime: process.uptime(),
    memoryUsage: process.memoryUsage(),
    version: process.version,
    platform: process.platform,
    timestamp: Date.now()
  });
});

/**
 * GET /health/db
 * @description Checks the connectivity to the Firestore database.
 */
router.get('/health/db', async (req, res, next) => {
  try {
    // Perform a lightweight, non-critical read operation
    await db.collection('_health_check').limit(1).get();
    res.status(200).json({ status: 'ok', message: 'Firestore connection is healthy.' });
  } catch (error) {
    console.error('Firestore health check failed:', error);
    res.status(503).json({ status: 'error', message: 'Firestore connection failed.' });
  }
});


// -----------------------------------------------------------------------------
// 6. ERROR HANDLING
// -----------------------------------------------------------------------------
app.use('/api', router);

// Catch-all for 404 Not Found errors
app.use((req, res, next) => {
  res.status(404).json({ error: `Not Found - ${req.originalUrl}` });
});

// Generic error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  // Do not leak stack trace in production
  const errorResponse = {
    error: err.message || 'An unexpected error occurred.',
  };

  if (process.env.NODE_ENV !== 'production') {
    errorResponse.stack = err.stack;
  }

  res.status(err.status || 500).json(errorResponse);
});


// -----------------------------------------------------------------------------
// 7. SERVER STARTUP
// -----------------------------------------------------------------------------
if (cluster.isMaster) {
  console.log(`Master ${process.pid} is running`);

  // Fork workers for each CPU core.
  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }

  cluster.on('exit', (worker, code, signal) => {
    console.log(`Worker ${worker.process.pid} died. Forking another one.`);
    cluster.fork();
  });
} else {
  app.listen(PORT, () => {
    console.log(`Worker ${process.pid} started. Server running on http://localhost:${PORT}`);
  });
}

