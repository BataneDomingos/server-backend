require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const PDFDocument = require('pdfkit');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 5000;
const isDev = process.env.NODE_ENV === 'development';

// Middleware
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Determinar o caminho correto para os arquivos estáticos
let staticPath;
let indexPath;

if (isDev) {
  // Em modo de desenvolvimento, usar o dist local
  staticPath = path.join(__dirname, '..', 'dist');
  indexPath = path.join(staticPath, 'index.html');
} else {
  // Em produção (executável), os arquivos estão no mesmo diretório do executável
  staticPath = path.join(process.cwd(), 'dist');
  indexPath = path.join(staticPath, 'index.html');
  
  // Fallback: tentar outras localizações possíveis
  if (!fs.existsSync(staticPath)) {
    staticPath = path.join(__dirname, 'dist');
    indexPath = path.join(staticPath, 'index.html');
  }
  
  if (!fs.existsSync(staticPath)) {
    staticPath = path.join(process.resourcesPath, 'dist');
    indexPath = path.join(staticPath, 'index.html');
  }
}

console.log('Static path:', staticPath);
console.log('Index path:', indexPath);
console.log('Static path exists:', fs.existsSync(staticPath));
console.log('Index file exists:', fs.existsSync(indexPath));

// Servir arquivos estáticos
if (fs.existsSync(staticPath)) {
  app.use(express.static(staticPath));
} else {
  console.warn('Warning: Static files directory not found at:', staticPath);
}

// Database Connection
const dbConfig = {
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 3306, // Adiciona essa linha
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
};

// Create database connection pool
const pool = mysql.createPool(dbConfig);

// Test database connection
async function testConnection() {
  try {
    const connection = await pool.getConnection();
    console.log('Database connection successful');
    connection.release();
  } catch (error) {
    console.error('Database connection failed:', error);
    // Don't exit in production, continue without database
    if (isDev) {
      process.exit(1);
    }
  }
}

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
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const [users] = await pool.query(
      'SELECT * FROM users WHERE username = ?',
      [username]
    );
    
    if (users.length === 0) {
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }
    
    const user = users[0];
    
    // Since we're storing passwords as plain text as requested
    if (password !== user.password) {
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }
    
    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'secret_key',
      { expiresIn: '24h' }
    );
    
    // Remove password from user object
    delete user.password;
    
    res.json({ token, user });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Erro no servidor' });
  }
});

// Dashboard data
app.get('/api/dashboard', authenticateToken, async (req, res) => {
  try {
    const dashboardData = {
      totalProducts: 0,
      lowStockProducts: 0,
      totalSales: 0,
      totalRevenue: 0,
      recentSales: [],
      topProducts: []
    };

    // Get total products
    const [productCount] = await pool.query('SELECT COUNT(*) as total FROM products');
    dashboardData.totalProducts = productCount[0].total;

    // Get low stock products (stock < 10)
    const [lowStockCount] = await pool.query('SELECT COUNT(*) as total FROM products WHERE stock < 10');
    dashboardData.lowStockProducts = lowStockCount[0].total;

    // Get total sales and revenue
    const [salesData] = await pool.query('SELECT COUNT(*) as total, COALESCE(SUM(total), 0) as revenue FROM sales');
    dashboardData.totalSales = salesData[0].total || 0;
    dashboardData.totalRevenue = parseFloat(salesData[0].revenue) || 0;

    // Get recent sales (last 5)
    const [recentSales] = await pool.query(`
      SELECT s.*, u.name as vendor_name 
      FROM sales s
      JOIN users u ON s.vendor_id = u.id
      ORDER BY s.date DESC
      LIMIT 5
    `);
    dashboardData.recentSales = recentSales || [];

    // Get top products
    const [topProducts] = await pool.query(`
      SELECT 
        si.product_name,
        SUM(si.quantity) as total_quantity,
        SUM(si.total) as total_sales
      FROM 
        sale_items si
      GROUP BY 
        si.product_id, si.product_name
      ORDER BY 
        total_quantity DESC
      LIMIT 5
    `);
    dashboardData.topProducts = topProducts || [];

    res.json(dashboardData);
  } catch (error) {
    console.error('Error fetching dashboard data:', error);
    res.status(500).json({ message: 'Erro ao buscar dados do dashboard' });
  }
});

// Products routes
app.get('/api/products', authenticateToken, async (req, res) => {
  try {
    const [products] = await pool.query('SELECT * FROM products ORDER BY name');
    res.json(products || []);
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ message: 'Erro ao buscar produtos' });
  }
});

app.get('/api/products/:id', authenticateToken, async (req, res) => {
  try {
    const [products] = await pool.query(
      'SELECT * FROM products WHERE id = ?',
      [req.params.id]
    );
    
    if (products.length === 0) {
      return res.status(404).json({ message: 'Produto não encontrado' });
    }
    
    res.json(products[0]);
  } catch (error) {
    console.error('Error fetching product:', error);
    res.status(500).json({ message: 'Erro ao buscar produto' });
  }
});

// Create product with serial_code duplicate check
app.post('/api/products', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { name, category, price, stock, serial_code } = req.body;

    // Check for duplicate serial_code
    const [existingProducts] = await pool.query(
      'SELECT * FROM products WHERE serial_code = ?',
      [serial_code]
    );

    if (existingProducts.length > 0) {
      return res.status(400).json({ message: 'Código serial já está em uso' });
    }

    const [result] = await pool.query(
      'INSERT INTO products (name, category, price, stock, serial_code) VALUES (?, ?, ?, ?, ?)',
      [name, category, price, stock, serial_code]
    );

    const id = result.insertId;
    res.status(201).json({ id, name, category, price, stock, serial_code });
  } catch (error) {
    console.error('Error creating product:', error);
    if (error.code === 'ER_BAD_FIELD_ERROR') {
      return res.status(500).json({ message: 'Erro: Coluna serial_code não encontrada na tabela de produtos. Contate o administrador.' });
    }
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ message: 'Código serial já está em uso' });
    }
    res.status(500).json({ message: 'Erro ao criar produto' });
  }
});

// Update product with serial_code duplicate check
app.put('/api/products/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { name, category, price, stock, serial_code } = req.body;

    // Check for duplicate serial_code, excluding the current product
    const [existingProducts] = await pool.query(
      'SELECT * FROM products WHERE serial_code = ? AND id != ?',
      [serial_code, req.params.id]
    );

    if (existingProducts.length > 0) {
      return res.status(400).json({ message: 'Código serial já está em uso' });
    }

    await pool.query(
      'UPDATE products SET name = ?, category = ?, price = ?, stock = ?, serial_code = ? WHERE id = ?',
      [name, category, price, stock, serial_code, req.params.id]
    );

    res.json({ id: parseInt(req.params.id), name, category, price, stock, serial_code });
  } catch (error) {
    console.error('Error updating product:', error);
    if (error.code === 'ER_BAD_FIELD_ERROR') {
      return res.status(500).json({ message: 'Erro: Coluna serial_code não encontrada na tabela de produtos. Contate o administrador.' });
    }
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ message: 'Código serial já está em uso' });
    }
    res.status(500).json({ message: 'Erro ao atualizar produto' });
  }
});

// Delete product
app.delete('/api/products/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM products WHERE id = ?',
      [req.params.id]
    );
    
    res.status(204).send();
  } catch (error) {
    console.error('Error deleting product:', error);
    res.status(500).json({ message: 'Erro ao excluir produto' });
  }
});

// Users routes
app.get('/api/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const [users] = await pool.query('SELECT id, username, name, role FROM users');
    res.json(users || []);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Erro ao buscar usuários' });
  }
});

app.get('/api/users/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const [users] = await pool.query(
      'SELECT * FROM users WHERE id = ?',
      [req.params.id]
    );
    
    if (users.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }
    
    const user = users[0];
    res.json(user);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ message: 'Erro ao buscar usuário' });
  }
});

app.post('/api/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { username, password, name, role } = req.body;
    
    // Check if username already exists
    const [existingUsers] = await pool.query(
      'SELECT * FROM users WHERE username = ?',
      [username]
    );
    
    if (existingUsers.length > 0) {
      return res.status(400).json({ message: 'Nome de usuário já existe' });
    }
    
    const [result] = await pool.query(
      'INSERT INTO users (username, password, name, role) VALUES (?, ?, ?, ?)',
      [username, password, name, role]
    );
    
    const id = result.insertId;
    res.status(201).json({ id, username, name, role });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ message: 'Erro ao criar usuário' });
  }
});

app.put('/api/users/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { username, password, name, role } = req.body;
    
    if (password) {
      await pool.query(
        'UPDATE users SET username = ?, password = ?, name = ?, role = ? WHERE id = ?',
        [username, password, name, role, req.params.id]
      );
    } else {
      await pool.query(
        'UPDATE users SET username = ?, name = ?, role = ? WHERE id = ?',
        [username, name, role, req.params.id]
      );
    }
    
    res.json({ id: parseInt(req.params.id), username, name, role });
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ message: 'Erro ao atualizar usuário' });
  }
});

app.delete('/api/users/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM users WHERE id = ?',
      [req.params.id]
    );
    
    res.status(204).send();
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ message: 'Erro ao excluir usuário' });
  }
});

// Sales routes
app.get('/api/sales', authenticateToken, async (req, res) => {
  try {
    let query = `
      SELECT s.*, u.name as vendor_name 
      FROM sales s
      JOIN users u ON s.vendor_id = u.id
    `;
    
    const params = [];
    
    // If not admin, only show own sales
    if (req.user.role !== 'admin') {
      query += ' WHERE s.vendor_id = ?';
      params.push(req.user.id);
    }
    
    query += ' ORDER BY s.date DESC';
    
    const [sales] = await pool.query(query, params);
    
    // Get items for each sale
    for (const sale of sales) {
      const [items] = await pool.query(
        'SELECT * FROM sale_items WHERE sale_id = ?',
        [sale.id]
      );
      sale.items = items || [];
    }
    
    res.json(sales || []);
  } catch (error) {
    console.error('Error fetching sales:', error);
    res.status(500).json({ message: 'Erro ao buscar vendas' });
  }
});

app.get('/api/sales/:id', authenticateToken, async (req, res) => {
  try {
    const [sales] = await pool.query(
      `SELECT s.*, u.name as vendor_name 
       FROM sales s
       JOIN users u ON s.vendor_id = u.id
       WHERE s.id = ?`,
      [req.params.id]
    );
    
    if (sales.length === 0) {
      return res.status(404).json({ message: 'Venda não encontrada' });
    }
    
    const sale = sales[0];
    
    // Check if user has access to this sale
    if (req.user.role !== 'admin' && sale.vendor_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }
    
    // Get items for this sale
    const [items] = await pool.query(
      'SELECT * FROM sale_items WHERE sale_id = ?',
      [sale.id]
    );
    
    sale.items = items || [];
    
    res.json(sale);
  } catch (error) {
    console.error('Error fetching sale:', error);
    res.status(500).json({ message: 'Erro ao buscar venda' });
  }
});

app.post('/api/sales', authenticateToken, async (req, res) => {
  const connection = await pool.getConnection();
  
  try {
    await connection.beginTransaction();
    
    const { vendor_id, total, payment, change, items } = req.body;
    
    // Input validation
    if (!items || !Array.isArray(items) || items.length === 0) {
      throw new Error('A venda deve conter pelo menos um item');
    }
    
    // Validate stock for all items
    for (const item of items) {
      if (!item.product_id || !item.quantity || item.quantity <= 0) {
        throw new Error(`Dados inválidos para o item: ${item.product_name || 'Desconhecido'}`);
      }
      
      const [productRows] = await connection.query(
        'SELECT stock, name FROM products WHERE id = ?',
        [item.product_id]
      );
      
      if (productRows.length === 0) {
        throw new Error(`Produto com ID ${item.product_id} não encontrado`);
      }
      
      const product = productRows[0];
      if (product.stock < item.quantity) {
        throw new Error(
          `Estoque insuficiente para ${product.name}. Disponível: ${product.stock}, Solicitado: ${item.quantity}`
        );
      }
    }
    
    // Insert sale
    const [saleResult] = await connection.query(
      'INSERT INTO sales (vendor_id, date, total, payment, change_amount) VALUES (?, NOW(), ?, ?, ?)',
      [vendor_id, total, payment, change]
    );
    
    const saleId = saleResult.insertId;
    
    // Insert sale items and update product stock
    for (const item of items) {
      await connection.query(
        'INSERT INTO sale_items (sale_id, product_id, product_name, price, quantity, total) VALUES (?, ?, ?, ?, ?, ?)',
        [saleId, item.product_id, item.product_name, item.price, item.quantity, item.total]
      );
      
      // Update product stock
      await connection.query(
        'UPDATE products SET stock = stock - ? WHERE id = ?',
        [item.quantity, item.product_id]
      );
    }
    
    await connection.commit();
    
    // Get the created sale with items
    const [createdSales] = await connection.query(
      `SELECT s.*, u.name as vendor_name 
       FROM sales s
       JOIN users u ON s.vendor_id = u.id
       WHERE s.id = ?`,
      [saleId]
    );
    
    const createdSale = createdSales[0];
    
    // Get items for this sale
    const [saleItems] = await connection.query(
      'SELECT * FROM sale_items WHERE sale_id = ?',
      [saleId]
    );
    
    createdSale.items = saleItems || [];
    
    res.status(201).json(createdSale);
  } catch (error) {
    await connection.rollback();
    console.error('Error creating sale:', error);
    res.status(400).json({ message: error.message || 'Erro ao criar venda' });
  } finally {
    connection.release();
  }
});

// Categories route
app.get('/api/categories', authenticateToken, async (req, res) => {
  try {
    const [categories] = await pool.query('SELECT DISTINCT category FROM products WHERE category IS NOT NULL AND category != "" ORDER BY category');
    const categoryList = categories.map(row => row.category);
    res.json(categoryList || []);
  } catch (error) {
    console.error('Error fetching categories:', error);
    res.status(500).json({ message: 'Erro ao buscar categorias' });
  }
});

// Reports routes
app.get('/api/reports/sales', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    
    let query = `
      SELECT s.*, u.name as vendor_name 
      FROM sales s
      JOIN users u ON s.vendor_id = u.id
    `;
    
    const params = [];
    
    if (startDate && endDate) {
      query += ' WHERE s.date BETWEEN ? AND ?';
      params.push(startDate, endDate);
    }
    
    query += ' ORDER BY s.date DESC';
    
    const [sales] = await pool.query(query, params);
    
    // Get items for each sale
    for (const sale of sales) {
      const [items] = await pool.query(
        'SELECT * FROM sale_items WHERE sale_id = ?',
        [sale.id]
      );
      sale.items = items || [];
    }
    
    res.json(sales || []);
  } catch (error) {
    console.error('Error fetching sales report:', error);
    res.status(500).json({ message: 'Erro ao buscar relatório de vendas' });
  }
});

app.get('/api/reports/top-products', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { limit } = req.query;
    const limitValue = limit ? parseInt(limit) : 10;
    
    const [topProducts] = await pool.query(`
      SELECT 
        si.product_id,
        si.product_name,
        SUM(si.quantity) as total_quantity,
        SUM(si.total) as total_sales
      FROM 
        sale_items si
      GROUP BY 
        si.product_id, si.product_name
      ORDER BY 
        total_quantity DESC
      LIMIT ?
    `, [limitValue]);
    
    res.json(topProducts || []);
  } catch (error) {
    console.error('Error fetching top products:', error);
    res.status(500).json({ message: 'Erro ao buscar produtos mais vendidos' });
  }
});

app.get('/api/reports/sales-by-vendor/:vendorId', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { vendorId } = req.params;
    
    const [sales] = await pool.query(`
      SELECT 
        s.*,
        u.name as vendor_name
      FROM 
        sales s
      JOIN 
        users u ON s.vendor_id = u.id
      WHERE 
        s.vendor_id = ?
      ORDER BY 
        s.date DESC
    `, [vendorId]);
    
    res.json(sales || []);
  } catch (error) {
    console.error('Error fetching sales by vendor:', error);
    res.status(500).json({ message: 'Erro ao buscar vendas por vendedor' });
  }
});

// Generate receipt PDF
app.get('/api/receipts/:id', authenticateToken, async (req, res) => {
  try {
    const [sales] = await pool.query(
      `SELECT s.*, u.name as vendor_name 
       FROM sales s
       JOIN users u ON s.vendor_id = u.id
       WHERE s.id = ?`,
      [req.params.id]
    );

    if (sales.length === 0) {
      return res.status(404).json({ message: 'Venda não encontrada' });
    }

    const sale = sales[0];

    // Check if user has access to this sale
    if (req.user.role !== 'admin' && sale.vendor_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    const [items] = await pool.query(
      'SELECT * FROM sale_items WHERE sale_id = ?',
      [sale.id]
    );

    // Create PDF
    const doc = new PDFDocument();
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=recibo-venda-${sale.id}.pdf`);
    doc.pipe(res);

    // Header
    doc.fontSize(20).text('RECIBO DE VENDA', { align: 'center' });
    doc.fontSize(12).text('Sistema de Gestão de Loja', { align: 'center' });
    doc.moveDown();

    // Sale details
    doc.fontSize(10);
    doc.text(`Venda #: ${sale.id}`);
    doc.text(`Data: ${new Date(sale.date).toLocaleDateString('pt-BR')} ${new Date(sale.date).toLocaleTimeString('pt-BR')}`);
    doc.text(`Vendedor: ${sale.vendor_name || 'Desconhecido'}`);
    doc.moveDown();

    // Items table
    const tableTop = doc.y;
    const itemWidth = 200;
    const priceWidth = 80;
    const qtyWidth = 50;
    const totalWidth = 80;
    const startX = 50;

    // Headers
    doc.fontSize(10).font('Helvetica-Bold');
    doc.text('Produto', startX, tableTop);
    doc.text('Preço Unit.', startX + itemWidth, tableTop, { width: priceWidth, align: 'right' });
    doc.text('Qtd', startX + itemWidth + priceWidth, tableTop, { width: qtyWidth, align: 'right' });
    doc.text('Total', startX + itemWidth + priceWidth + qtyWidth, tableTop, { width: totalWidth, align: 'right' });

    // Divider
    doc.moveTo(startX, tableTop + 15).lineTo(startX + itemWidth + priceWidth + qtyWidth + totalWidth, tableTop + 15).stroke();

    // Rows
    doc.font('Helvetica');
    let y = tableTop + 20;
    items.forEach((item) => {
      doc.text(item.product_name || 'N/A', startX, y, { width: itemWidth });
      doc.text(
        `MZN ${Number(item.price).toFixed(2)}`,
        startX + itemWidth,
        y,
        { width: priceWidth, align: 'right' }
      );
      doc.text(item.quantity.toString(), startX + itemWidth + priceWidth, y, { width: qtyWidth, align: 'right' });
      doc.text(
        `MZN ${Number(item.total).toFixed(2)}`,
        startX + itemWidth + priceWidth + qtyWidth,
        y,
        { width: totalWidth, align: 'right' }
      );
      y += 15;
    });

    // Summary
    y += 10;
    doc.font('Helvetica-Bold');
    doc.text(`Total: MZN ${Number(sale.total).toFixed(2)}`, startX + itemWidth + priceWidth + qtyWidth, y, {
      width: totalWidth,
      align: 'right',
    });
    y += 15;
    doc.text(`Pagamento: MZN ${Number(sale.payment).toFixed(2)}`, startX + itemWidth + priceWidth + qtyWidth, y, {
      width: totalWidth,
      align: 'right',
    });
    y += 15;
    doc.text(`Troco: MZN ${Number(sale.change_amount).toFixed(2)}`, startX + itemWidth + priceWidth + qtyWidth, y, {
      width: totalWidth,
      align: 'right',
    });

    // Footer
    doc.font('Helvetica').fontSize(8);
    doc.text('Obrigado pela preferência!', 0, y + 25, { align: 'center', width: 595 });

    doc.end();
  } catch (error) {
    console.error('Error generating receipt:', error);
    res.status(500).json({ message: 'Erro ao gerar recibo' });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'Server is running' });
});

// Catch-all handler: send back React's index.html file for client-side routing
app.get('*', (req, res) => {
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(404).json({ 
      error: 'Frontend files not found',
      message: 'Please build the frontend first using "npm run build"',
      searchedPaths: [staticPath, indexPath]
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    message: isDev ? err.message : 'Something went wrong'
  });
});

// Database initialization
async function initializeDatabase() {
  const connection = await pool.getConnection();
  
  try {
    // Create users table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        name VARCHAR(100) NOT NULL,
        role ENUM('admin', 'vendor') NOT NULL
      )
    `);
    
    // Create products table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS products (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        category VARCHAR(50) NOT NULL,
        price DECIMAL(10, 2) NOT NULL,
        stock INT NOT NULL DEFAULT 0,
        serial_code VARCHAR(100) UNIQUE
      )
    `);
    
    // Check if serial_code column exists, add if missing
    const [columns] = await connection.query(
      `SELECT COLUMN_NAME 
       FROM INFORMATION_SCHEMA.COLUMNS 
       WHERE TABLE_NAME = 'products' AND TABLE_SCHEMA = ?`,
      [dbConfig.database]
    );
    const hasSerialCode = columns.some(col => col.COLUMN_NAME === 'serial_code');
    
    if (!hasSerialCode) {
      await connection.query(`
        ALTER TABLE products
        ADD COLUMN serial_code VARCHAR(100) UNIQUE
      `);
      console.log('Added serial_code column to products table');
      
      // Populate serial_code for existing products
      const [products] = await connection.query('SELECT id FROM products');
      for (const product of products) {
        await connection.query(
          'UPDATE products SET serial_code = ? WHERE id = ?',
          [`SN${String(product.id).padStart(3, '0')}`, product.id]
        );
      }
      console.log('Populated serial_code for existing products');
    }
    
    // Create sales table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS sales (
        id INT AUTO_INCREMENT PRIMARY KEY,
        vendor_id INT NOT NULL,
        date DATETIME NOT NULL,
        total DECIMAL(10, 2) NOT NULL,
        payment DECIMAL(10, 2) NOT NULL,
        change_amount DECIMAL(10, 2) NOT NULL,
        FOREIGN KEY (vendor_id) REFERENCES users(id)
      )
    `);
    
    // Create sale_items table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS sale_items (
        id INT AUTO_INCREMENT PRIMARY KEY,
        sale_id INT NOT NULL,
        product_id INT NOT NULL,
        product_name VARCHAR(100) NOT NULL,
        price DECIMAL(10, 2) NOT NULL,
        quantity INT NOT NULL,
        total DECIMAL(10, 2) NOT NULL,
        FOREIGN KEY (sale_id) REFERENCES sales(id) ON DELETE CASCADE
      )
    `);
    
    // Check if default admin exists
    const [admins] = await connection.query('SELECT * FROM users WHERE role = "admin"');
    
    // Create default admin if none exists
    if (admins.length === 0) {
      await connection.query(`
        INSERT INTO users (username, password, name, role)
        VALUES ('admin', 'admin123', 'Administrador', 'admin')
      `);
      console.log('Default admin user created');
    }
    
    // Add sample products if none exist
    const [products] = await connection.query('SELECT * FROM products');

    if (products.length === 0) {
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

      for (const product of sampleProducts) {
        await connection.query(
          'INSERT INTO products (serial_code, name, category, price, stock) VALUES (?, ?, ?, ?, ?)',
          product
        );
      }

      console.log('Sample products inserted.');
    }
    
    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Error initializing database:', error);
  } finally {
    connection.release();
  }
}

// Start the server
async function startServer() {
  try {
    await testConnection();
    await initializeDatabase();
    
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
      console.log(`Environment: ${isDev ? 'development' : 'production'}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
  }
}

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  process.exit(0);
});

startServer();