// server.js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const { sql, getPool } = require('./dbConfig');
const https = require('https');
const fs = require('fs');
const { body, validationResult } = require('express-validator'); // for input validation

const app = express();
// app.set("trust proxy", 1);
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const path = require('path');

// Multer Storage
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const dir = './uploads';
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    cb(null, dir);
  },
  filename: function (req, file, cb) {
    // Unique name: timestamp-originalname
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage: storage });

const corsOptions = {
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  maxAge: 86400 // 24 hours
};

// 🚫 Bruteforce protection for login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: 'Too many login attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
});

// 🌐 General limiter for all /api routes
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});

// 1️⃣ SECURITY HEADERS FIRST
const helmet = require('helmet');

app.use(helmet()); // Base Helmet protections

app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  })
);

app.use(
  helmet.hsts({
    maxAge: 31536000,
    includeSubDomains: true,
  })
);


app.use(cors(corsOptions));

app.use(bodyParser.json());


const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Attach user info to request
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

const roleMiddleware = (requiredRole) => {
  return (req, res, next) => {
    if (req.user.role !== requiredRole) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};


app.use('/api/projects', authMiddleware);


app.use(session({
  secret: process.env.SESSION_SECRET || 'dev_session_secret',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));

const JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret';

/* --------------------- AUTH MIDDLEWARE ---------------------- */

// Verify token
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Missing token" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
}

// Admin-only middleware
function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin access required" });
  }
  next();
}

/* --------------------- AUTH ROUTES ---------------------- */

// Register
app.post('/api/register', async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: 'username/password required' });

  const hash = await bcrypt.hash(password, 10);

  try {
    const pool = await getPool();
    await pool.request()
      .input('username', sql.NVarChar(50), username)
      .input('passwordHash', sql.NVarChar(255), hash)
      .input('role', sql.NVarChar(50), role || null)
      .query('INSERT INTO Users (Username, PasswordHash, Role) VALUES (@username,@passwordHash,@role)');
    res.json({ message: 'User registered' });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ message: 'Error registering user' });
  }
});

// Login


app.post(
  '/api/login',
  loginLimiter,
  [
    body('username')
      .exists().withMessage('Username is required')
      .isString().withMessage('Invalid username format')
      .trim()
      .escape()
      .isLength({ min: 3, max: 255 })
      .withMessage('Username must be 3–255 characters'),

    body('password')
      .exists().withMessage('Password is required')
      .isString().withMessage('Invalid password format')
      .isLength({ min: 8, max: 255 })
      .withMessage('Password must be 8–255 characters')
  ],
  async (req, res) => {
    // Validation errors?
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    let { username, password } = req.body;

    try {
      const pool = await getPool();

      const result = await pool
        .request()
        .input('username', sql.NVarChar(255), username)
        .query(`
          SELECT TOP 1 UserID, Username, PasswordHash, Role
          FROM Users
          WHERE Username = @username COLLATE SQL_Latin1_General_CP1_CI_AS
        `);

      if (!result.recordset.length) {
        return res.status(400).json({ message: "User not found" });
      }

      const user = result.recordset[0];

      const match = await bcrypt.compare(password, user.PasswordHash);
      if (!match) {
        return res.status(400).json({ message: "Invalid password" });
      }

      const token = jwt.sign(
        { id: user.UserID, username: user.Username, role: user.Role },
        JWT_SECRET,
        { expiresIn: '2h' }
      );

      return res.json({
        success: true,
        token,
        user: {
          id: user.UserID,
          username: user.Username,
          role: user.Role
        }
      });

    } catch (err) {
      console.error("Login error:", err);
      return res.status(500).json({ message: "Internal server error" });
    }
  }
);

app.use('/api/', generalLimiter);


/* --------------------- PROJECT APIS ---------------------- */

// Get all projects
app.get('/api/projects', authenticateToken, async (req, res) => {
  try {
    const pool = await getPool();
    const result = await pool.request().query("SELECT * FROM Projects ORDER BY ProjectID DESC");
    res.json(result.recordset);
  } catch (err) {
    console.error("Fetch projects error:", err);
    res.status(500).json({ message: "Error fetching projects" });
  }
});

// Create project
app.post('/api/projects', authenticateToken, async (req, res) => {
  const { Name, StartDate, EndDate, Status, Progress, Owner, Notes } = req.body;

  try {
    const pool = await getPool();
    const result = await pool.request()
      .input("Name", sql.NVarChar(255), Name)
      .input("StartDate", sql.Date, StartDate || null)
      .input("EndDate", sql.Date, EndDate || null)
      .input("Status", sql.NVarChar(50), Status || null)
      .input("Progress", sql.Int, Progress || 0)
      .input("Owner", sql.NVarChar(100), Owner || null)
      .input("Notes", sql.NVarChar(sql.MAX), Notes || null)
      .query(`
        INSERT INTO Projects (Name, StartDate, EndDate, Status, Progress, Owner, Notes)
        VALUES (@Name, @StartDate, @EndDate, @Status, @Progress, @Owner, @Notes);
        SELECT SCOPE_IDENTITY() AS ProjectID;
      `);

    res.json(result.recordset[0]);
  } catch (err) {
    console.error("Add project error:", err);
    res.status(500).json({ message: "Error adding project" });
  }
});

// Update Project
app.put('/api/projects/:projectId', authenticateToken, async (req, res) => {
  const { projectId } = req.params;
  const { Name, StartDate, EndDate, Status, Progress, Owner, Notes } = req.body;

  try {
    const pool = await getPool();
    await pool.request()
      .input("ProjectID", sql.Int, projectId)
      .input("Name", sql.NVarChar(255), Name)
      .input("StartDate", sql.Date, StartDate || null)
      .input("EndDate", sql.Date, EndDate || null)
      .input("Status", sql.NVarChar(50), Status || null)
      .input("Progress", sql.Int, Progress || 0)
      .input("Owner", sql.NVarChar(100), Owner || null)
      .input("Notes", sql.NVarChar(sql.MAX), Notes || null)
      .query(`
        UPDATE Projects SET 
          Name = @Name,
          StartDate = @StartDate,
          EndDate = @EndDate,
          Status = @Status,
          Progress = @Progress,
          Owner = @Owner,
          Notes = @Notes
        WHERE ProjectID = @ProjectID
      `);

    res.json({ message: "Project updated" });
  } catch (err) {
    console.error("Update project error:", err);
    res.status(500).json({ message: "Error updating project" });
  }
});

// Update Category
app.put('/api/categories/:categoryId', authenticateToken, async (req, res) => {
  const { categoryId } = req.params;
  const { Name, StartDate, EndDate, Status, Progress, Owner, Notes } = req.body;

  try {
    const pool = await getPool();
    await pool.request()
      .input("CategoryID", sql.Int, categoryId)
      .input("Name", sql.NVarChar(255), Name)
      .input("StartDate", sql.Date, StartDate || null)
      .input("EndDate", sql.Date, EndDate || null)
      .input("Status", sql.NVarChar(50), Status || null)
      .input("Progress", sql.Int, Progress || 0)
      .input("Owner", sql.NVarChar(100), Owner || null)
      .input("Notes", sql.NVarChar(sql.MAX), Notes || null)
      .query(`
        UPDATE Categories SET
          Name = @Name,
          StartDate = @StartDate,
          EndDate = @EndDate,
          Status = @Status,
          Progress = @Progress,
          Owner = @Owner,
          Notes = @Notes
        WHERE CategoryID = @CategoryID
      `);

    res.json({ message: "Category updated" });
  } catch (err) {
    console.error("Update category error:", err);
    res.status(500).json({ message: "Error updating category" });
  }
});

// Update Task
app.put('/api/tasks/:taskId', authenticateToken, async (req, res) => {
  const { taskId } = req.params;
  const { Name, StartDate, EndDate, Status, Progress, Owner, Notes } = req.body;

  try {
    const pool = await getPool();
    await pool.request()
      .input("TaskID", sql.Int, taskId)
      .input("Name", sql.NVarChar(255), Name)
      .input("StartDate", sql.Date, StartDate || null)
      .input("EndDate", sql.Date, EndDate || null)
      .input("Status", sql.NVarChar(50), Status || null)
      .input("Progress", sql.Int, Progress || 0)
      .input("Owner", sql.NVarChar(100), Owner || null)
      .input("Notes", sql.NVarChar(sql.MAX), Notes || null)
      .query(`
        UPDATE Tasks SET
          Name = @Name,
          StartDate = @StartDate,
          EndDate = @EndDate,
          Status = @Status,
          Progress = @Progress,
          Owner = @Owner,
          Notes = @Notes
        WHERE TaskID = @TaskID
      `);

    res.json({ message: "Task updated" });
  } catch (err) {
    console.error("Update task error:", err);
    res.status(500).json({ message: "Error updating task" });
  }
});




// Delete project (admin only)
app.delete('/api/projects/:projectId', authenticateToken, roleMiddleware('admin'), async (req, res) => {
  const { projectId } = req.params;

  try {
    const pool = await getPool();
    await pool.request().input("ProjectID", sql.Int, projectId).query(`
      DELETE FROM SubTasks WHERE TaskID IN (
        SELECT TaskID FROM ProjectTasks WHERE ProjectID = @ProjectID
      );
      DELETE FROM ProjectTasks WHERE ProjectID = @ProjectID;
      DELETE FROM Categories WHERE ProjectID = @ProjectID;
      DELETE FROM ProjectMembers WHERE ProjectID = @ProjectID;
      DELETE FROM Projects WHERE ProjectID = @ProjectID;
    `);

    res.json({ message: "Project deleted successfully" });
  } catch (err) {
    console.error("Delete project error:", err);
    res.status(500).json({ message: "Error deleting project" });
  }
});

/* --------------------- CATEGORY APIS ---------------------- */

// Get categories for project
app.get('/api/categories/:projectId', authenticateToken, async (req, res) => {
  const { projectId } = req.params;

  try {
    const pool = await getPool();
    const result = await pool.request()
      .input("projectId", sql.Int, projectId)
      .query("SELECT * FROM Categories WHERE ProjectID = @projectId ORDER BY CategoryID DESC");

    res.json(result.recordset);
  } catch (err) {
    console.error("Fetch categories error:", err);
    res.status(500).json({ message: "Error fetching categories" });
  }
});

// Add category
app.post('/api/categories', authenticateToken, async (req, res) => {
  const { ProjectID, Name, StartDate, EndDate, Status, Progress, Owner, Notes } = req.body;

  try {
    const pool = await getPool();
    const result = await pool.request()
      .input("ProjectID", sql.Int, ProjectID)
      .input("Name", sql.NVarChar(255), Name)
      .input("StartDate", sql.Date, StartDate || null)
      .input("EndDate", sql.Date, EndDate || null)
      .input("Status", sql.NVarChar(50), Status || null)
      .input("Progress", sql.Int, Progress || 0)
      .input("Owner", sql.NVarChar(100), Owner || null)
      .input("Notes", sql.NVarChar(sql.MAX), Notes || null)
      .query(`
        INSERT INTO Categories (ProjectID, Name, StartDate, EndDate, Status, Progress, Owner, Notes)
        VALUES (@ProjectID, @Name, @StartDate, @EndDate, @Status, @Progress, @Owner, @Notes);
        SELECT SCOPE_IDENTITY() AS CategoryID;
      `);

    res.json(result.recordset[0]);
  } catch (err) {
    console.error("Add category error:", err);
    res.status(500).json({ message: "Error adding category" });
  }
});

// Delete category (admin only)
app.delete('/api/categories/:categoryId', authenticateToken, requireAdmin, async (req, res) => {
  const { categoryId } = req.params;

  try {
    const pool = await getPool();
    await pool.request().input("CategoryID", sql.Int, categoryId).query(`
      DELETE FROM Tasks WHERE CategoryID = @CategoryID;
      DELETE FROM Categories WHERE CategoryID = @CategoryID;
    `);

    res.json({ message: "Category deleted successfully" });
  } catch (err) {
    console.error("Delete category error:", err);
    res.status(500).json({ message: "Error deleting category" });
  }
});

/* --------------------- TASK APIS ---------------------- */

app.get('/api/tasks/:categoryId', authenticateToken, async (req, res) => {
  const { categoryId } = req.params;

  try {
    const pool = await getPool();
    const result = await pool.request()
      .input("categoryId", sql.Int, categoryId)
      .query("SELECT * FROM Tasks WHERE CategoryID = @categoryId ORDER BY TaskID DESC");

    res.json(result.recordset);
  } catch (err) {
    console.error("Fetch tasks error:", err);
    res.status(500).json({ message: "Error fetching tasks" });
  }
});

// Add task
app.post('/api/tasks', authenticateToken, async (req, res) => {
  const { CategoryID, ParentTaskID, Name, StartDate, EndDate, Status, Progress, Owner, Notes } = req.body;

  try {
    const pool = await getPool();
    const result = await pool.request()
      .input("CategoryID", sql.Int, CategoryID)
      .input("ParentTaskID", sql.Int, ParentTaskID || null)
      .input("Name", sql.NVarChar(255), Name)
      .input("StartDate", sql.Date, StartDate || null)
      .input("EndDate", sql.Date, EndDate || null)
      .input("Status", sql.NVarChar(50), Status || null)
      .input("Progress", sql.Int, Progress || 0)
      .input("Owner", sql.NVarChar(100), Owner || null)
      .input("Notes", sql.NVarChar(sql.MAX), Notes || null)
      .query(`
        INSERT INTO Tasks (CategoryID, ParentTaskID, Name, StartDate, EndDate, Status, Progress, Owner, Notes)
        VALUES (@CategoryID, @ParentTaskID, @Name, @StartDate, @EndDate, @Status, @Progress, @Owner, @Notes);
        SELECT SCOPE_IDENTITY() AS TaskID;
      `);

    res.json(result.recordset[0]);
  } catch (err) {
    console.error("Add task error:", err);
    res.status(500).json({ message: "Error adding task" });
  }
});

// Delete task (admin only)
app.delete('/api/tasks/:taskId', authenticateToken, requireAdmin, async (req, res) => {
  const { taskId } = req.params;

  try {
    const pool = await getPool();
    await pool.request().input("TaskID", sql.Int, taskId).query(`
      DELETE FROM SubTasks WHERE TaskID = @TaskID;
      DELETE FROM Tasks WHERE TaskID = @TaskID;
    `);

    res.json({ message: "Task deleted successfully" });
  } catch (err) {
    console.error("Delete task error:", err);
    res.status(500).json({ message: "Error deleting task" });
  }
});

/* --------------------- SUBTASK APIS ---------------------- */

app.get('/api/subtasks/:taskId', authenticateToken, async (req, res) => {
  const { taskId } = req.params;

  try {
    const pool = await getPool();
    const result = await pool.request()
      .input("TaskID", sql.Int, taskId)
      .query("SELECT * FROM SubTasks WHERE TaskID = @TaskID ORDER BY SubTaskID DESC");

    res.json(result.recordset);
  } catch (err) {
    console.error("Fetch subtasks error:", err);
    res.status(500).json({ message: "Error fetching subtasks" });
  }
});

// Add Subtask
app.post('/api/subtasks', authenticateToken, async (req, res) => {
  let { TaskID, Name, StartDate, EndDate, StatusID, Progress, OwnerID, Notes } = req.body;

  try {
    // Convert
    StatusID = StatusID ? parseInt(StatusID) : null;
    OwnerID = OwnerID ? parseInt(OwnerID) : null;
    Progress = Progress ? parseInt(Progress) : 0;
    TaskID = parseInt(TaskID);

    // Date validation
    if (StartDate && EndDate) {
      const s = new Date(StartDate);
      const e = new Date(EndDate);
      if (e < s) {
        return res.status(400).json({ message: "End Date cannot be before Start Date" });
      }
    }

    const pool = await getPool();
    const result = await pool.request()
      .input("TaskID", sql.Int, TaskID)
      .input("Name", sql.NVarChar(200), Name)
      .input("StartDate", sql.Date, StartDate || null)
      .input("EndDate", sql.Date, EndDate || null)
      .input("StatusID", sql.Int, StatusID)
      .input("Progress", sql.Int, Progress)
      .input("OwnerID", sql.Int, OwnerID)
      .input("Notes", sql.NVarChar(sql.MAX), Notes || null)
      .query(`
        INSERT INTO SubTasks (TaskID, Name, StartDate, EndDate, StatusID, Progress, OwnerID, Notes)
        VALUES (@TaskID, @Name, @StartDate, @EndDate, @StatusID, @Progress, @OwnerID, @Notes);
        SELECT SCOPE_IDENTITY() AS SubTaskID;
      `);

    res.json(result.recordset[0]);

  } catch (err) {
    console.error("Add subtask error:", err);
    res.status(500).json({ message: "Error adding subtask" });
  }
});


// Delete Subtask (admin only)
app.delete('/api/subtasks/:subTaskId', authenticateToken, requireAdmin, async (req, res) => {
  const { subTaskId } = req.params;

  try {
    const pool = await getPool();
    await pool.request()
      .input("SubTaskID", sql.Int, subTaskId)
      .query("DELETE FROM SubTasks WHERE SubTaskID = @SubTaskID");

    res.json({ message: "SubTask deleted successfully" });
  } catch (err) {
    console.error("Delete subtask error:", err);
    res.status(500).json({ message: "Error deleting subtask" });
  }
});

/* --------------------- PROJECT MEMBERS APIS ---------------------- */

app.get('/api/project-members/:projectId', authenticateToken, async (req, res) => {
  const { projectId } = req.params;

  try {
    const pool = await getPool();
    const result = await pool.request()
      .input("ProjectID", sql.Int, projectId)
      .query(`
        SELECT PM.MemberID, U.UserID, U.Username, U.Role
        FROM ProjectMembers PM
        JOIN Users U ON PM.UserID = U.UserID
        WHERE PM.ProjectID = @ProjectID
      `);

    res.json(result.recordset);
  } catch (err) {
    console.error("Fetch project members error:", err);
    res.status(500).json({ message: "Error fetching members" });
  }
});

// Add Project Member
app.post('/api/project-members', authenticateToken, async (req, res) => {
  const { ProjectID, UserID, Username } = req.body;

  try {
    const pool = await getPool();
    let userId = UserID;

    // If Username is provided instead of UserID, look up the user
    if (!userId && Username) {
      const userResult = await pool.request()
        .input("Username", sql.NVarChar(255), Username)
        .query(`
          SELECT TOP 1 UserID
          FROM Users
          WHERE Username = @Username COLLATE SQL_Latin1_General_CP1_CI_AS
        `);

      if (!userResult.recordset.length) {
        return res.status(400).json({ message: "User not found" });
      }

      userId = userResult.recordset[0].UserID;
    }

    if (!userId) {
      return res.status(400).json({ message: "UserID or Username is required" });
    }

    const result = await pool.request()
      .input("ProjectID", sql.Int, ProjectID)
      .input("UserID", sql.Int, userId)
      .query(`
        INSERT INTO ProjectMembers (ProjectID, UserID)
        VALUES (@ProjectID, @UserID);
        SELECT SCOPE_IDENTITY() AS MemberID;
      `);

    res.json(result.recordset[0]);
  } catch (err) {
    console.error("Add member error:", err);
    if (err.number === 2627) { // SQL Server duplicate key error
      res.status(400).json({ message: "User is already a member of this project" });
    } else {
      res.status(500).json({ message: "Error adding project member" });
    }
  }
});

// Delete project member (admin only)
app.delete('/api/project-members/:memberId', authenticateToken, requireAdmin, async (req, res) => {
  const { memberId } = req.params;

  try {
    const pool = await getPool();

    await pool.request()
      .input("MemberID", sql.Int, memberId)
      .query("DELETE FROM ProjectMembers WHERE MemberID = @MemberID");

    res.json({ message: "Member removed from project" });
  } catch (err) {
    console.error("Delete member error:", err);
    res.status(500).json({ message: "Error deleting member" });
  }
});



// server.js or routes/status.js
app.get('/api/status', async (req, res) => {
  try {
    const pool = await getPool(); // ensures connection is open
    const result = await pool.request().query('SELECT StatusID, StatusName FROM statusMaster');
    res.json(result.recordset);
  } catch (err) {
    console.error('Error fetching status:', err);
    res.status(500).send('Server error');
  }
});



/* --------------------- ATTACHMENT APIS ---------------------- */

// Upload Attachment
app.post('/api/attachments', authenticateToken, upload.single('file'), async (req, res) => {
  const { entityId, entityType } = req.body; // e.g., 'Project', 'Category', 'Task'
  const file = req.file;

  if (!file) {
    return res.status(400).json({ message: "No file uploaded" });
  }

  try {
    const pool = await getPool();
    const result = await pool.request()
      .input("EntityID", sql.Int, entityId)
      .input("EntityType", sql.NVarChar(50), entityType)
      .input("FileName", sql.NVarChar(255), file.originalname)
      .input("FilePath", sql.NVarChar(500), file.path)
      .input("UploadedBy", sql.NVarChar(100), req.user.username)
      .query(`
        INSERT INTO Attachments (EntityID, EntityType, FileName, FilePath, UploadedBy)
        VALUES (@EntityID, @EntityType, @FileName, @FilePath, @UploadedBy);
        SELECT SCOPE_IDENTITY() AS AttachmentID;
      `);

    res.json({
      message: "File uploaded successfully",
      attachmentId: result.recordset[0].AttachmentID,
      fileName: file.originalname,
      filePath: file.path
    });

  } catch (err) {
    console.error("Upload error:", err);
    res.status(500).json({ message: "Error uploading file" });
  }
});

// Get Attachments for Entity
app.get('/api/attachments/:entityType/:entityId', authenticateToken, async (req, res) => {
  const { entityType, entityId } = req.params;

  try {
    const pool = await getPool();
    const result = await pool.request()
      .input("EntityID", sql.Int, entityId)
      .input("EntityType", sql.NVarChar(50), entityType)
      .query(`
        SELECT AttachmentID, FileName, UploadedBy, UploadDate 
        FROM Attachments 
        WHERE EntityID = @EntityID AND EntityType = @EntityType
        ORDER BY UploadDate DESC
      `);

    res.json(result.recordset);
  } catch (err) {
    console.error("Fetch attachments error:", err);
    res.status(500).json({ message: "Error fetching attachments" });
  }
});

// Download Attachment
app.get('/api/attachments/:id/download', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const pool = await getPool();
    const result = await pool.request()
      .input("AttachmentID", sql.Int, id)
      .query("SELECT FileName, FilePath FROM Attachments WHERE AttachmentID = @AttachmentID");

    if (!result.recordset.length) {
      return res.status(404).json({ message: "File not found" });
    }

    const { FileName, FilePath } = result.recordset[0];
    const absolutePath = path.resolve(FilePath);

    res.download(absolutePath, FileName, (err) => {
      if (err) {
        console.error("Download error:", err);
        // header might be sent, so end
        if (!res.headersSent) res.status(500).send("Error downloading file");
      }
    });

  } catch (err) {
    console.error("Download error:", err);
    res.status(500).json({ message: "Error retrieving file" });
  }
});

// Delete Attachment
app.delete('/api/attachments/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const pool = await getPool();

    // Get file path first
    const pathResult = await pool.request()
      .input("AttachmentID", sql.Int, id)
      .query("SELECT FilePath, UploadedBy FROM Attachments WHERE AttachmentID = @AttachmentID");

    if (!pathResult.recordset.length) {
      return res.status(404).json({ message: "File not found" });
    }

    const { FilePath, UploadedBy } = pathResult.recordset[0];

    // Optional: Check if user is owner or admin
    if (req.user.role !== 'admin' && req.user.username !== UploadedBy) {
      return res.status(403).json({ message: "You can only delete files you uploaded" });
    }

    // Delete record from DB
    await pool.request()
      .input("AttachmentID", sql.Int, id)
      .query("DELETE FROM Attachments WHERE AttachmentID = @AttachmentID");

    // Delete file from disk
    const absolutePath = path.resolve(FilePath);
    fs.unlink(absolutePath, (err) => {
      if (err) console.error("File deletion error (disk):", err);
    });

    res.json({ message: "Attachment deleted" });

  } catch (err) {
    console.error("Delete attachment error:", err);
    res.status(500).json({ message: "Error deleting attachment" });
  }
});


/* --------------------- START SERVER ---------------------- */

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
