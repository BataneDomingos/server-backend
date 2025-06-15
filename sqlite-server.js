// Versão alternativa do servidor usando SQLite para melhor portabilidade
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const PDFDocument = require('pdfkit');
const path = require('path');

const app = express();
const port = process.env.PORT || 5000;

// Middlewares
app.use(cors());
app.use(express.json());
app.use(cookieParser());

// Servir arquivos estáticos do build do React
app.use(express.static(path.join(__dirname, '..', 'dist')));

// Database Connection - SQLite
const dbPath = path.join(__dirname, 'shop_management.db');
const db = new Database(dbPath);

// Enable foreign keys
db.pragma('foreign_keys = ON');

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ message: 'Acesso não autorizado' });
  
  jwt.verify(token, process.env.JWT_SECRET || 'secret_key', (err, user) => {
    if (err) return res.status(403).json({ message: 'Token inválido' });
    req.user = user;
    next();
  });
};

// Admin role middleware
const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Acesso negado. Requer privilégios de administrador.' });
  }
  next();
};

// Authentication routes
app.post('/api/auth/login', (req, res) => {
  try {
    const { username, password } = req.body;
    
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    
    if (!user) {
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }
    
    if (password !== user.password) {
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }
    
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'secret_key',
      { expiresIn: '24h' }
    );
    
    delete user.password;
    
    res.json({ token, user });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Erro no servidor' });
  }
});

// Products routes
app.get('/api/products', authenticateToken, (req, res) => {
  try {
    const products = db.prepare('SELECT * FROM products').all();
    res.json(products);
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ message: 'Erro ao buscar produtos' });
  }
});

app.get('/api/products/:id', authenticateToken, (req, res) => {
  try {
    const product = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
    
    if (!product) {
      return res.status(404).json({ message: 'Produto não encontrado' });
    }
    
    res.json(product);
  } catch (error) {
    console.error('Error fetching product:', error);
    res.status(500).json({ message: 'Erro ao buscar produto' });
  }
});

app.post('/api/products', authenticateToken, isAdmin, (req, res) => {
  try {
    const { name, category, price, stock, serial_code } = req.body;

    const existingProduct = db.prepare('SELECT * FROM products WHERE serial_code = ?').get(serial_code);

    if (existingProduct) {
      return res.status(400).json({ message: 'Código serial já está em uso' });
    }

    const stmt = db.prepare('INSERT INTO products (name, category, price, stock, serial_code) VALUES (?, ?, ?, ?, ?)');
    const result = stmt.run(name, category, price, stock, serial_code);

    res.status(201).json({ id: result.lastInsertRowid, name, category, price, stock, serial_code });
  } catch (error) {
    console.error('Error creating product:', error);
    res.status(500).json({ message: 'Erro ao criar produto' });
  }
});

app.put('/api/products/:id', authenticateToken, isAdmin, (req, res) => {
  try {
    const { name, category, price, stock, serial_code } = req.body;

    const existingProduct = db.prepare('SELECT * FROM products WHERE serial_code = ? AND id != ?').get(serial_code, req.params.id);

    if (existingProduct) {
      return res.status(400).json({ message: 'Código serial já está em uso' });
    }

    const stmt = db.prepare('UPDATE products SET name = ?, category = ?, price = ?, stock = ?, serial_code = ? WHERE id = ?');
    stmt.run(name, category, price, stock, serial_code, req.params.id);

    res.json({ id: parseInt(req.params.id), name, category, price, stock, serial_code });
  } catch (error) {
    console.error('Error updating product:', error);
    res.status(500).json({ message: 'Erro ao atualizar produto' });
  }
});

app.delete('/api/products/:id', authenticateToken, isAdmin, (req, res) => {
  try {
    const stmt = db.prepare('DELETE FROM products WHERE id = ?');
    stmt.run(req.params.id);
    
    res.status(204).send();
  } catch (error) {
    console.error('Error deleting product:', error);
    res.status(500).json({ message: 'Erro ao excluir produto' });
  }
});

// Users routes
app.get('/api/users', authenticateToken, isAdmin, (req, res) => {
  try {
    const users = db.prepare('SELECT id, username, name, role FROM users').all();
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Erro ao buscar usuários' });
  }
});

app.post('/api/users', authenticateToken, isAdmin, (req, res) => {
  try {
    const { username, password, name, role } = req.body;
    
    const existingUser = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    
    if (existingUser) {
      return res.status(400).json({ message: 'Nome de usuário já existe' });
    }
    
    const stmt = db.prepare('INSERT INTO users (username, password, name, role) VALUES (?, ?, ?, ?)');
    const result = stmt.run(username, password, name, role);
    
    res.status(201).json({ id: result.lastInsertRowid, username, name, role });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ message: 'Erro ao criar usuário' });
  }
});

// Sales routes
app.get('/api/sales', authenticateToken, (req, res) => {
  try {
    let query = `
      SELECT s.*, u.name as vendor_name 
      FROM sales s
      JOIN users u ON s.vendor_id = u.id
    `;
    
    let sales;
    
    if (req.user.role !== 'admin') {
      query += ' WHERE s.vendor_id = ?';
      sales = db.prepare(query + ' ORDER BY s.date DESC').all(req.user.id);
    } else {
      sales = db.prepare(query + ' ORDER BY s.date DESC').all();
    }
    
    // Get items for each sale
    const itemsStmt = db.prepare('SELECT * FROM sale_items WHERE sale_id = ?');
    for (const sale of sales) {
      sale.items = itemsStmt.all(sale.id);
    }
    
    res.json(sales);
  } catch (error) {
    console.error('Error fetching sales:', error);
    res.status(500).json({ message: 'Erro ao buscar vendas' });
  }
});

app.post('/api/sales', authenticateToken, (req, res) => {
  try {
    const { vendor_id, vendor_name, total, payment, change, items } = req.body;
    
    if (!items || !Array.isArray(items) || items.length === 0) {
      throw new Error('A venda deve conter pelo menos um item');
    }
    
    // Start transaction
    const transaction = db.transaction(() => {
      // Validate stock for all items
      for (const item of items) {
        if (!item.product_id || !item.quantity || item.quantity <= 0) {
          throw new Error(`Dados inválidos para o item: ${item.product_name || 'Desconhecido'}`);
        }
        
        const product = db.prepare('SELECT stock, name FROM products WHERE id = ?').get(item.product_id);
        
        if (!product) {
          throw new Error(`Produto com ID ${item.product_id} não encontrado`);
        }
        
        if (product.stock < item.quantity) {
          throw new Error(
            `Estoque insuficiente para ${product.name}. Disponível: ${product.stock}, Solicitado: ${item.quantity}`
          );
        }
      }
      
      // Insert sale
      const saleStmt = db.prepare('INSERT INTO sales (vendor_id, date, total, payment, change_amount) VALUES (?, datetime("now"), ?, ?, ?)');
      const saleResult = saleStmt.run(vendor_id, total, payment, change);
      const saleId = saleResult.lastInsertRowid;
      
      // Insert sale items and update product stock
      const itemStmt = db.prepare('INSERT INTO sale_items (sale_id, product_id, product_name, price, quantity, total) VALUES (?, ?, ?, ?, ?, ?)');
      const stockStmt = db.prepare('UPDATE products SET stock = stock - ? WHERE id = ?');
      
      for (const item of items) {
        itemStmt.run(saleId, item.product_id, item.product_name, item.price, item.quantity, item.total);
        stockStmt.run(item.quantity, item.product_id);
      }
      
      return saleId;
    });
    
    const saleId = transaction();
    
    // Get the created sale with items
    const createdSale = db.prepare(`
      SELECT s.*, u.name as vendor_name 
      FROM sales s
      JOIN users u ON s.vendor_id = u.id
      WHERE s.id = ?
    `).get(saleId);
    
    createdSale.items = db.prepare('SELECT * FROM sale_items WHERE sale_id = ?').all(saleId);
    
    res.status(201).json(createdSale);
  } catch (error) {
    console.error('Error creating sale:', error);
    res.status(400).json({ message: error.message || 'Erro ao criar venda' });
  }
});

// Categories route
app.get('/api/categories', authenticateToken, (req, res) => {
  try {
    const categories = db.prepare('SELECT DISTINCT category FROM products WHERE category IS NOT NULL AND category != "" ORDER BY category').all();
    const categoryList = categories.map(row => row.category);
    res.json(categoryList);
  } catch (error) {
    console.error('Error fetching categories:', error);
    res.status(500).json({ message: 'Erro ao buscar categorias' });
  }
});

// Catch-all handler: send back React's index.html file for client-side routing
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'dist', 'index.html'));
});

// Database initialization
function initializeDatabase() {
  try {
    // Create users table
    db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        name TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('admin', 'vendor'))
      )
    `);
    
    // Create products table
    db.exec(`
      CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        price REAL NOT NULL,
        stock INTEGER NOT NULL DEFAULT 0,
        serial_code TEXT UNIQUE
      )
    `);
    
    // Create sales table
    db.exec(`
      CREATE TABLE IF NOT EXISTS sales (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vendor_id INTEGER NOT NULL,
        date TEXT NOT NULL,
        total REAL NOT NULL,
        payment REAL NOT NULL,
        change_amount REAL NOT NULL,
        FOREIGN KEY (vendor_id) REFERENCES users(id)
      )
    `);
    
    // Create sale_items table
    db.exec(`
      CREATE TABLE IF NOT EXISTS sale_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sale_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        product_name TEXT NOT NULL,
        price REAL NOT NULL,
        quantity INTEGER NOT NULL,
        total REAL NOT NULL,
        FOREIGN KEY (sale_id) REFERENCES sales(id) ON DELETE CASCADE
      )
    `);
    
    // Check if default admin exists
    const adminExists = db.prepare('SELECT COUNT(*) as count FROM users WHERE role = "admin"').get();
    
    if (adminExists.count === 0) {
      db.prepare('INSERT INTO users (username, password, name, role) VALUES (?, ?, ?, ?)').run('admin', 'admin123', 'Administrador', 'admin');
      console.log('Default admin user created');
    }
    
    // Add sample products if none exist
    const productCount = db.prepare('SELECT COUNT(*) as count FROM products').get();
    
    if (productCount.count === 0) {
      const sampleProducts = [
        ['SN001', 'Notebook HP', 'Eletrônicos', 25000.00, 5],
        ['SN002', 'Smartphone Samsung', 'Eletrônicos', 8000.00, 10],
        ['SN003', 'Televisão LG 43"', 'Eletrônicos', 12000.00, 3],
        ['SN004', 'Teclado Sem Fio', 'Acessórios', 1500.00, 15],
        ['SN005', 'Mouse Bluetooth', 'Acessórios', 800.00, 20],
        ['SN006', 'Cadeira de Escritório', 'Móveis', 3500.00, 7],
        ['SN007', 'Mesa de Trabalho', 'Móveis', 4500.00, 4],
        ['SN008', 'Fones de Ouvido', 'Acessórios', 1200.00, 12]
      ];

      const stmt = db.prepare('INSERT INTO products (serial_code, name, category, price, stock) VALUES (?, ?, ?, ?, ?)');
      
      for (const product of sampleProducts) {
        stmt.run(...product);
      }

      console.log('Sample products inserted.');
    }
    
    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Error initializing database:', error);
  }
}

// Start the server
try {
  initializeDatabase();
  
  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
} catch (error) {
  console.error('Failed to start server:', error);
}