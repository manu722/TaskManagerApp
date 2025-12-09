const { sql, getPool } = require('./dbConfig');

async function createAttachmentsTable() {
    try {
        const pool = await getPool();
        await pool.request().query(`
      IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='Attachments' AND xtype='U')
      CREATE TABLE Attachments (
          AttachmentID INT IDENTITY(1,1) PRIMARY KEY,
          EntityID INT NOT NULL,
          EntityType NVARCHAR(50) NOT NULL, -- 'Project', 'Category', 'Task', 'SubTask'
          FileName NVARCHAR(255) NOT NULL,
          FilePath NVARCHAR(500) NOT NULL,
          UploadedBy NVARCHAR(100),
          UploadDate DATETIME DEFAULT GETDATE()
      );
    `);
        console.log("Attachments table created or already exists.");
    } catch (err) {
        console.error("Error creating Attachments table:", err);
    } finally {
        process.exit();
    }
}

createAttachmentsTable();
