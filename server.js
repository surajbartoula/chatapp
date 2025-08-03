import Fastify from 'fastify';
import cors from '@fastify/cors';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import { Server } from 'socket.io';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const fastify = Fastify({ logger: true });

// Register plugins
await fastify.register(cors, {
  origin: true,
  credentials: true
});

// Database setup
const db = await open({
  filename: path.join(__dirname, 'chat.db'),
  driver: sqlite3.Database
});

// Initialize database tables
await db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_online BOOLEAN DEFAULT FALSE
  );

  CREATE TABLE IF NOT EXISTS friend_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users (id),
    FOREIGN KEY (receiver_id) REFERENCES users (id),
    UNIQUE(sender_id, receiver_id)
  );

  CREATE TABLE IF NOT EXISTS friendships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user1_id INTEGER NOT NULL,
    user2_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user1_id) REFERENCES users (id),
    FOREIGN KEY (user2_id) REFERENCES users (id),
    UNIQUE(user1_id, user2_id)
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users (id),
    FOREIGN KEY (recipient_id) REFERENCES users (id)
  );

  CREATE TABLE IF NOT EXISTS blocked_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    blocker_id INTEGER NOT NULL,
    blocked_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (blocker_id) REFERENCES users (id),
    FOREIGN KEY (blocked_id) REFERENCES users (id),
    UNIQUE(blocker_id, blocked_id)
  );

  CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id);
  CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id);
  CREATE INDEX IF NOT EXISTS idx_blocked_users ON blocked_users(blocker_id, blocked_id);
  CREATE INDEX IF NOT EXISTS idx_friend_requests ON friend_requests(receiver_id, status);
  CREATE INDEX IF NOT EXISTS idx_friendships ON friendships(user1_id, user2_id);
`);

// Store active Socket.IO connections
const connectedUsers = new Map();

// Utility functions
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

async function getUserById(id) {
  return await db.get('SELECT id, username, is_online, last_seen FROM users WHERE id = ?', [id]);
}

async function isBlocked(blockerId, blockedId) {
  const result = await db.get(
    'SELECT 1 FROM blocked_users WHERE blocker_id = ? AND blocked_id = ?',
    [blockerId, blockedId]
  );
  return !!result;
}

async function areFriends(userId1, userId2) {
  const result = await db.get(`
    SELECT 1 FROM friendships 
    WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)
  `, [userId1, userId2, userId2, userId1]);
  return !!result;
}

// Serve static files
fastify.register(import('@fastify/static'), {
  root: path.join(__dirname, 'public'),
  prefix: '/'
});

// API Routes
fastify.post('/api/register', async (request, reply) => {
  const { username, password } = request.body;
  
  if (!username || !password) {
    return reply.status(400).send({ error: 'Username and password required' });
  }

  try {
    const passwordHash = hashPassword(password);
    const result = await db.run(
      'INSERT INTO users (username, password_hash) VALUES (?, ?)',
      [username, passwordHash]
    );
    
    const user = await getUserById(result.lastID);
    const token = generateToken();
    
    reply.send({ user, token });
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return reply.status(400).send({ error: 'Username already exists' });
    }
    reply.status(500).send({ error: 'Registration failed' });
  }
});

fastify.post('/api/login', async (request, reply) => {
  const { username, password } = request.body;
  
  if (!username || !password) {
    return reply.status(400).send({ error: 'Username and password required' });
  }

  try {
    const passwordHash = hashPassword(password);
    const user = await db.get(
      'SELECT id, username, is_online FROM users WHERE username = ? AND password_hash = ?',
      [username, passwordHash]
    );
    
    if (!user) {
      return reply.status(401).send({ error: 'Invalid credentials' });
    }

    await db.run('UPDATE users SET is_online = TRUE, last_seen = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);
    
    const token = generateToken();
    reply.send({ user, token });
  } catch (error) {
    reply.status(500).send({ error: 'Login failed' });
  }
});

fastify.get('/api/users', async (request, reply) => {
  const currentUserId = parseInt(request.headers['user-id']);
  
  if (!currentUserId) {
    return reply.status(401).send({ error: 'User not authenticated' });
  }

  try {
    const users = await db.all(
      'SELECT id, username, is_online, last_seen FROM users WHERE id != ? ORDER BY username',
      [currentUserId]
    );
    reply.send(users);
  } catch (error) {
    reply.status(500).send({ error: 'Failed to fetch users' });
  }
});

fastify.get('/api/friends', async (request, reply) => {
  const currentUserId = parseInt(request.headers['user-id']);
  
  if (!currentUserId) {
    return reply.status(401).send({ error: 'User not authenticated' });
  }

  try {
    const friends = await db.all(`
      SELECT u.id, u.username, u.is_online, u.last_seen
      FROM users u
      JOIN friendships f ON (
        (f.user1_id = ? AND f.user2_id = u.id) OR 
        (f.user2_id = ? AND f.user1_id = u.id)
      )
      ORDER BY u.username
    `, [currentUserId, currentUserId]);
    
    reply.send(friends);
  } catch (error) {
    reply.status(500).send({ error: 'Failed to fetch friends' });
  }
});

fastify.post('/api/friend-request', async (request, reply) => {
  const senderId = parseInt(request.headers['user-id']);
  const { receiverId } = request.body;
  
  if (!senderId || !receiverId) {
    return reply.status(400).send({ error: 'Invalid request' });
  }

  if (senderId === receiverId) {
    return reply.status(400).send({ error: 'Cannot send friend request to yourself' });
  }

  try {
    // Check if already friends
    const alreadyFriends = await areFriends(senderId, receiverId);
    if (alreadyFriends) {
      return reply.status(400).send({ error: 'Already friends with this user' });
    }

    // Check if request already exists
    const existingRequest = await db.get(
      'SELECT * FROM friend_requests WHERE sender_id = ? AND receiver_id = ? AND status = "pending"',
      [senderId, receiverId]
    );
    
    if (existingRequest) {
      return reply.status(400).send({ error: 'Friend request already sent' });
    }

    // Check if blocked
    const blocked = await isBlocked(receiverId, senderId);
    if (blocked) {
      return reply.status(400).send({ error: 'Cannot send friend request to this user' });
    }

    await db.run(
      'INSERT INTO friend_requests (sender_id, receiver_id) VALUES (?, ?)',
      [senderId, receiverId]
    );
    
    reply.send({ success: true });
  } catch (error) {
    reply.status(500).send({ error: 'Failed to send friend request' });
  }
});

fastify.get('/api/friend-requests', async (request, reply) => {
  const currentUserId = parseInt(request.headers['user-id']);
  
  if (!currentUserId) {
    return reply.status(401).send({ error: 'User not authenticated' });
  }

  try {
    const requests = await db.all(`
      SELECT fr.id, fr.sender_id, fr.created_at, u.username as sender_username
      FROM friend_requests fr
      JOIN users u ON fr.sender_id = u.id
      WHERE fr.receiver_id = ? AND fr.status = "pending"
      ORDER BY fr.created_at DESC
    `, [currentUserId]);
    
    reply.send(requests);
  } catch (error) {
    reply.status(500).send({ error: 'Failed to fetch friend requests' });
  }
});

fastify.post('/api/friend-request/accept', async (request, reply) => {
  const receiverId = parseInt(request.headers['user-id']);
  const { requestId } = request.body;
  
  if (!receiverId || !requestId) {
    return reply.status(400).send({ error: 'Invalid request' });
  }

  try {
    // Get the friend request
    const friendRequest = await db.get(
      'SELECT * FROM friend_requests WHERE id = ? AND receiver_id = ? AND status = "pending"',
      [requestId, receiverId]
    );
    
    if (!friendRequest) {
      return reply.status(404).send({ error: 'Friend request not found' });
    }

    // Create friendship (ensure smaller ID is user1_id for consistency)
    const [user1_id, user2_id] = [friendRequest.sender_id, receiverId].sort((a, b) => a - b);
    
    await db.run('BEGIN TRANSACTION');
    
    // Update friend request status
    await db.run(
      'UPDATE friend_requests SET status = "accepted", updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [requestId]
    );
    
    // Create friendship
    await db.run(
      'INSERT INTO friendships (user1_id, user2_id) VALUES (?, ?)',
      [user1_id, user2_id]
    );
    
    await db.run('COMMIT');
    
    reply.send({ success: true });
  } catch (error) {
    await db.run('ROLLBACK');
    reply.status(500).send({ error: 'Failed to accept friend request' });
  }
});

fastify.post('/api/friend-request/reject', async (request, reply) => {
  const receiverId = parseInt(request.headers['user-id']);
  const { requestId } = request.body;
  
  if (!receiverId || !requestId) {
    return reply.status(400).send({ error: 'Invalid request' });
  }

  try {
    await db.run(
      'UPDATE friend_requests SET status = "rejected", updated_at = CURRENT_TIMESTAMP WHERE id = ? AND receiver_id = ?',
      [requestId, receiverId]
    );
    
    reply.send({ success: true });
  } catch (error) {
    reply.status(500).send({ error: 'Failed to reject friend request' });
  }
});

fastify.get('/api/messages/:userId', async (request, reply) => {
  const currentUserId = parseInt(request.headers['user-id']);
  const otherUserId = parseInt(request.params.userId);
  
  if (!currentUserId) {
    return reply.status(401).send({ error: 'User not authenticated' });
  }

  try {
    // Check if users are friends
    const friends = await areFriends(currentUserId, otherUserId);
    if (!friends) {
      return reply.status(403).send({ error: 'You can only message friends' });
    }

    const messages = await db.all(`
      SELECT m.*, u.username as sender_username 
      FROM messages m
      JOIN users u ON m.sender_id = u.id
      WHERE (
        (m.sender_id = ? AND m.recipient_id = ?) OR 
        (m.sender_id = ? AND m.recipient_id = ?)
      )
      ORDER BY m.created_at ASC
    `, [currentUserId, otherUserId, otherUserId, currentUserId]);
    
    reply.send(messages);
  } catch (error) {
    reply.status(500).send({ error: 'Failed to fetch messages' });
  }
});

fastify.post('/api/block', async (request, reply) => {
  const blockerId = parseInt(request.headers['user-id']);
  const { userId } = request.body;
  
  if (!blockerId || !userId) {
    return reply.status(400).send({ error: 'Invalid request' });
  }

  try {
    await db.run(
      'INSERT OR IGNORE INTO blocked_users (blocker_id, blocked_id) VALUES (?, ?)',
      [blockerId, userId]
    );
    reply.send({ success: true });
  } catch (error) {
    reply.status(500).send({ error: 'Failed to block user' });
  }
});

fastify.post('/api/unblock', async (request, reply) => {
  const blockerId = parseInt(request.headers['user-id']);
  const { userId } = request.body;
  
  if (!blockerId || !userId) {
    return reply.status(400).send({ error: 'Invalid request' });
  }

  try {
    await db.run(
      'DELETE FROM blocked_users WHERE blocker_id = ? AND blocked_id = ?',
      [blockerId, userId]
    );
    reply.send({ success: true });
  } catch (error) {
    reply.status(500).send({ error: 'Failed to unblock user' });
  }
});

fastify.get('/api/blocked', async (request, reply) => {
  const userId = parseInt(request.headers['user-id']);
  
  if (!userId) {
    return reply.status(401).send({ error: 'User not authenticated' });
  }

  try {
    const blocked = await db.all(`
      SELECT u.id, u.username 
      FROM blocked_users b
      JOIN users u ON b.blocked_id = u.id
      WHERE b.blocker_id = ?
    `, [userId]);
    reply.send(blocked);
  } catch (error) {
    reply.status(500).send({ error: 'Failed to fetch blocked users' });
  }
});

// Start server and setup Socket.IO
const start = async () => {
  try {
    await fastify.listen({ port: 3000, host: '0.0.0.0' });
    
    // Setup Socket.IO
    const io = new Server(fastify.server, {
      cors: {
        origin: "*",
        methods: ["GET", "POST"]
      }
    });

    // Socket.IO connection handling
    io.on('connection', (socket) => {
      let userId = null;
      let username = null;

      socket.on('authenticate', async (data) => {
        userId = data.userId;
        username = data.username;
        
        // Store user connection
        connectedUsers.set(userId, { socket, username });
        
        // Update user online status
        await db.run('UPDATE users SET is_online = TRUE WHERE id = ?', [userId]);
        
        // Notify friends that user is online
        const friends = await db.all(`
          SELECT CASE 
            WHEN f.user1_id = ? THEN f.user2_id 
            ELSE f.user1_id 
          END as friend_id
          FROM friendships f 
          WHERE f.user1_id = ? OR f.user2_id = ?
        `, [userId, userId, userId]);

        friends.forEach(friend => {
          const friendConnection = connectedUsers.get(friend.friend_id);
          if (friendConnection) {
            friendConnection.socket.emit('friend_online', {
              userId: userId,
              username: username
            });
          }
        });
        
        socket.emit('authenticated', { message: 'Connected successfully' });
      });

      socket.on('send_message', async (data) => {
        if (!userId) return;
        
        try {
          const recipientId = data.recipientId;
          
          // Check if users are friends
          const friends = await areFriends(userId, recipientId);
          if (!friends) {
            socket.emit('error', { message: 'You can only message friends' });
            return;
          }
          
          // Check if sender is blocked by recipient
          const blocked = await isBlocked(recipientId, userId);
          if (blocked) {
            socket.emit('error', { message: 'You are blocked by this user' });
            return;
          }
          
          // Save message to database
          const result = await db.run(
            'INSERT INTO messages (sender_id, recipient_id, content) VALUES (?, ?, ?)',
            [userId, recipientId, data.content]
          );
          
          const messageData = {
            id: result.lastID,
            sender_id: userId,
            recipient_id: recipientId,
            sender_username: username,
            content: data.content,
            created_at: new Date().toISOString()
          };
          
          // Send to recipient if online
          const recipientConnection = connectedUsers.get(recipientId);
          if (recipientConnection) {
            recipientConnection.socket.emit('new_message', messageData);
          }
          
          // Send confirmation to sender
          socket.emit('new_message', messageData);
        } catch (error) {
          socket.emit('error', { message: 'Failed to send message' });
        }
      });

      socket.on('typing_start', (data) => {
        if (!userId) return;
        
        const recipientConnection = connectedUsers.get(data.recipientId);
        if (recipientConnection) {
          recipientConnection.socket.emit('user_typing', {
            userId: userId,
            username: username,
            isTyping: true
          });
        }
      });

      socket.on('typing_stop', (data) => {
        if (!userId) return;
        
        const recipientConnection = connectedUsers.get(data.recipientId);
        if (recipientConnection) {
          recipientConnection.socket.emit('user_typing', {
            userId: userId,
            username: username,
            isTyping: false
          });
        }
      });

      socket.on('disconnect', async () => {
        if (userId) {
          connectedUsers.delete(userId);
          
          // Update user offline status
          await db.run('UPDATE users SET is_online = FALSE, last_seen = CURRENT_TIMESTAMP WHERE id = ?', [userId]);
          
          // Notify friends that user is offline
          const friends = await db.all(`
            SELECT CASE 
              WHEN f.user1_id = ? THEN f.user2_id 
              ELSE f.user1_id 
            END as friend_id
            FROM friendships f 
            WHERE f.user1_id = ? OR f.user2_id = ?
          `, [userId, userId, userId]);

          friends.forEach(friend => {
            const friendConnection = connectedUsers.get(friend.friend_id);
            if (friendConnection) {
              friendConnection.socket.emit('friend_offline', {
                userId: userId,
                username: username
              });
            }
          });
        }
      });
    });
    
    console.log('Server running on http://localhost:3000');
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();