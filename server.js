
### 9. server.js (Updated with production considerations)

```javascript
require('dotenv').config();
const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');

// Initialize Firebase Admin
let serviceAccount;

if (process.env.FIREBASE_PRIVATE_KEY) {
  // Use environment variables (Render)
  serviceAccount = {
    type: "service_account",
    project_id: process.env.FIREBASE_PROJECT_ID,
    private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    client_email: process.env.FIREBASE_CLIENT_EMAIL,
  };
} else {
  // Use service account file (local development)
  try {
    serviceAccount = require('./firebase-service-account.json');
  } catch (error) {
    console.error('Firebase service account file not found. Please provide Firebase credentials through environment variables.');
    process.exit(1);
  }
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL
});

const db = admin.firestore();
const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Request logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Helper Functions
const generatePath = async (parentId) => {
  if (!parentId) return '';
  return db.collection('entities').doc(parentId).get()
    .then(doc => {
      if (!doc.exists) return '';
      const parentData = doc.data();
      return parentData.path ? `${parentData.path}/${parentId}` : parentId;
    });
};

const updateDescendantPaths = async (entityId, parentPath) => {
  const newPath = parentPath ? `${parentPath}/${entityId}` : entityId;
  const batch = db.batch();
  
  const snapshot = await db.collection('entities')
    .where('parentId', '==', entityId)
    .get();
  
  for (const doc of snapshot.docs) {
    const descendantId = doc.id;
    const descendantPath = `${newPath}/${descendantId}`;
    
    batch.update(doc.ref, {
      path: descendantPath,
      depth: newPath.split('/').length,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    
    // Recursively update descendants
    await updateDescendantPaths(descendantId, newPath);
  }
  
  await batch.commit();
};

const getNextPosition = async (parentId) => {
  const snapshot = await db.collection('entities')
    .where('parentId', '==', parentId)
    .orderBy('position', 'desc')
    .limit(1)
    .get();
  
  if (snapshot.empty) return 0;
  return snapshot.docs[0].data().position + 1;
};

// Routes

// Create a new entity
app.post('/entities', async (req, res) => {
  try {
    const { name, email, role, parentId } = req.body;
    
    if (!name || !email || !role) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    // Get next position
    const position = await getNextPosition(parentId);
    
    // Generate path
    let path = '';
    let depth = 0;
    
    if (parentId) {
      const parentDoc = await db.collection('entities').doc(parentId).get();
      if (parentDoc.exists) {
        const parentData = parentDoc.data();
        path = parentData.path ? `${parentData.path}/${parentId}` : parentId;
        depth = parentData.depth + 1;
      }
    } else {
      path = ''; // Will be set to the document ID after creation
    }
    
    // Create entity
    const entityRef = db.collection('entities').doc();
    const entityId = entityRef.id;
    
    // Update path for root entities
    if (!parentId) {
      path = entityId;
    }
    
    const entityData = {
      id: entityId,
      name,
      email,
      role,
      parentId: parentId || null,
      position,
      path,
      depth,
      status: 'active',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      history: {
        roleChanges: [],
        hierarchyChanges: []
      },
      metrics: {
        descendantCount: 0,
        directChildrenCount: 0
      },
      customFields: {}
    };
    
    await entityRef.set(entityData);
    
    // Update parent's metrics
    if (parentId) {
      await db.collection('entities').doc(parentId).update({
        'metrics.directChildrenCount': admin.firestore.FieldValue.increment(1),
        'metrics.descendantCount': admin.firestore.FieldValue.increment(1),
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
      
      // Update ancestor metrics
      await updateAncestorMetrics(parentId);
    }
    
    res.status(201).json({ id: entityId, ...entityData });
  } catch (error) {
    console.error('Error creating entity:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get all entities (with optional filtering)
app.get('/entities', async (req, res) => {
  try {
    const { parentId, role } = req.query;
    let query = db.collection('entities');
    
    if (parentId) {
      query = query.where('parentId', '==', parentId);
    }
    
    if (role) {
      query = query.where('role', '==', role);
    }
    
    const snapshot = await query.orderBy('position').get();
    const entities = [];
    
    snapshot.forEach(doc => {
      entities.push({ id: doc.id, ...doc.data() });
    });
    
    res.json(entities);
  } catch (error) {
    console.error('Error fetching entities:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get a single entity by ID
app.get('/entities/:id', async (req, res) => {
  try {
    const entityDoc = await db.collection('entities').doc(req.params.id).get();
    
    if (!entityDoc.exists) {
      return res.status(404).json({ error: 'Entity not found' });
    }
    
    res.json({ id: entityDoc.id, ...entityDoc.data() });
  } catch (error) {
    console.error('Error fetching entity:', error);
    res.status(500).json({ error: error.message });
  }
});

// Update an entity
app.put('/entities/:id', async (req, res) => {
  try {
    const entityId = req.params.id;
    const { name, email, role, status, customFields } = req.body;
    
    const entityRef = db.collection('entities').doc(entityId);
    const entityDoc = await entityRef.get();
    
    if (!entityDoc.exists) {
      return res.status(404).json({ error: 'Entity not found' });
    }
    
    const entityData = entityDoc.data();
    const updateData = {
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    };
    
    // Track role changes
    if (role && role !== entityData.role) {
      updateData.role = role;
      updateData['history.roleChanges'] = admin.firestore.FieldValue.arrayUnion({
        fromRole: entityData.role,
        toRole: role,
        changedAt: admin.firestore.FieldValue.serverTimestamp(),
        changedBy: req.headers['user-id'] || 'system'
      });
    }
    
    // Update other fields
    if (name) updateData.name = name;
    if (email) updateData.email = email;
    if (status) updateData.status = status;
    if (customFields) updateData.customFields = customFields;
    
    await entityRef.update(updateData);
    
    const updatedDoc = await entityRef.get();
    res.json({ id: entityId, ...updatedDoc.data() });
  } catch (error) {
    console.error('Error updating entity:', error);
    res.status(500).json({ error: error.message });
  }
});

// Move an entity (change parent)
app.put('/entities/:id/move', async (req, res) => {
  try {
    const entityId = req.params.id;
    const { newParentId } = req.body;
    
    const entityRef = db.collection('entities').doc(entityId);
    const entityDoc = await entityRef.get();
    
    if (!entityDoc.exists) {
      return res.status(404).json({ error: 'Entity not found' });
    }
    
    const entityData = entityDoc.data();
    const oldParentId = entityData.parentId;
    
    if (oldParentId === newParentId) {
      return res.status(400).json({ error: 'Entity is already under this parent' });
    }
    
    // Get new position
    const position = await getNextPosition(newParentId);
    
    // Generate new path
    let newPath = '';
    let newDepth = 0;
    
    if (newParentId) {
      const parentDoc = await db.collection('entities').doc(newParentId).get();
      if (parentDoc.exists) {
        const parentData = parentDoc.data();
        newPath = parentData.path ? `${parentData.path}/${newParentId}` : newParentId;
        newDepth = parentData.depth + 1;
      }
    } else {
      newPath = entityId;
      newDepth = 0;
    }
    
    // Update entity
    const batch = db.batch();
    
    batch.update(entityRef, {
      parentId: newParentId || null,
      position,
      path: newPath,
      depth: newDepth,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      'history.hierarchyChanges': admin.firestore.FieldValue.arrayUnion({
        fromParentId: oldParentId,
        toParentId: newParentId,
        fromPosition: entityData.position,
        toPosition: position,
        changedAt: admin.firestore.FieldValue.serverTimestamp(),
        changedBy: req.headers['user-id'] || 'system'
      })
    });
    
    // Update old parent metrics
    if (oldParentId) {
      const oldParentRef = db.collection('entities').doc(oldParentId);
      batch.update(oldParentRef, {
        'metrics.directChildrenCount': admin.firestore.FieldValue.increment(-1),
        'metrics.descendantCount': admin.firestore.FieldValue.increment(-1 - entityData.metrics.descendantCount),
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
    }
    
    // Update new parent metrics
    if (newParentId) {
      const newParentRef = db.collection('entities').doc(newParentId);
      batch.update(newParentRef, {
        'metrics.directChildrenCount': admin.firestore.FieldValue.increment(1),
        'metrics.descendantCount': admin.firestore.FieldValue.increment(1 + entityData.metrics.descendantCount),
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
    }
    
    await batch.commit();
    
    // Update descendant paths
    await updateDescendantPaths(entityId, newPath);
    
    // Update ancestor metrics for both old and new parents
    if (oldParentId) {
      await updateAncestorMetrics(oldParentId);
    }
    if (newParentId) {
      await updateAncestorMetrics(newParentId);
    }
    
    const updatedDoc = await entityRef.get();
    res.json({ id: entityId, ...updatedDoc.data() });
  } catch (error) {
    console.error('Error moving entity:', error);
    res.status(500).json({ error: error.message });
  }
});

// Delete an entity
app.delete('/entities/:id', async (req, res) => {
  try {
    const entityId = req.params.id;
    const entityRef = db.collection('entities').doc(entityId);
    const entityDoc = await entityRef.get();
    
    if (!entityDoc.exists) {
      return res.status(404).json({ error: 'Entity not found' });
    }
    
    const entityData = entityDoc.data();
    
    // Check if entity has children
    const childrenSnapshot = await db.collection('entities')
      .where('parentId', '==', entityId)
      .get();
    
    if (!childrenSnapshot.empty) {
      return res.status(400).json({ 
        error: 'Cannot delete entity with children. Move or delete children first.' 
      });
    }
    
    // Update parent metrics
    if (entityData.parentId) {
      await db.collection('entities').doc(entityData.parentId).update({
        'metrics.directChildrenCount': admin.firestore.FieldValue.increment(-1),
        'metrics.descendantCount': admin.firestore.FieldValue.increment(-1),
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
      
      // Update ancestor metrics
      await updateAncestorMetrics(entityData.parentId);
    }
    
    // Delete entity
    await entityRef.delete();
    
    res.status(204).send();
  } catch (error) {
    console.error('Error deleting entity:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get entity hierarchy (subtree)
app.get('/entities/:id/hierarchy', async (req, res) => {
  try {
    const entityId = req.params.id;
    const entityDoc = await db.collection('entities').doc(entityId).get();
    
    if (!entityDoc.exists) {
      return res.status(404).json({ error: 'Entity not found' });
    }
    
    const entityData = entityDoc.data();
    const path = entityData.path;
    
    // Get all descendants using path prefix
    const snapshot = await db.collection('entities')
      .where('path', '>=', `${path}/`)
      .where('path', '<', `${path}0`)
      .orderBy('path')
      .get();
    
    const entities = [];
    entities.push({ id: entityId, ...entityData });
    
    snapshot.forEach(doc => {
      entities.push({ id: doc.id, ...doc.data() });
    });
    
    res.json(entities);
  } catch (error) {
    console.error('Error fetching hierarchy:', error);
    res.status(500).json({ error: error.message });
  }
});

// Helper function to update ancestor metrics
async function updateAncestorMetrics(entityId) {
  const entityDoc = await db.collection('entities').doc(entityId).get();
  if (!entityDoc.exists) return;
  
  const entityData = entityDoc.data();
  
  // Calculate direct children count
  const childrenSnapshot = await db.collection('entities')
    .where('parentId', '==', entityId)
    .get();
  
  const directChildrenCount = childrenSnapshot.size;
  
  // Calculate total descendant count
  const path = entityData.path;
  const descendantsSnapshot = await db.collection('entities')
    .where('path', '>=', `${path}/`)
    .where('path', '<', `${path}0`)
    .get();
  
  const descendantCount = descendantsSnapshot.size;
  
  // Update metrics
  await db.collection('entities').doc(entityId).update({
    'metrics.directChildrenCount': directChildrenCount,
    'metrics.descendantCount': descendantCount,
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  });
  
  // Recursively update ancestors
  if (entityData.parentId) {
    await updateAncestorMetrics(entityData.parentId);
  }
}

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
