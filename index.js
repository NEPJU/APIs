const fastify = require('fastify')();
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const cors = require('@fastify/cors');
const bcrypt = require('bcrypt');
const multipart = require('fastify-multipart');
const path = require('path');

fastify.register(multipart);
const uploadDir = path.join(__dirname, 'uploads');

// Create MySQL connection pool
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'root',
  database: 'phayao'
});

// Register the CORS plugin
fastify.register(cors, {
  // Set your desired options
  origin: '*',
  methods: ['GET', 'PUT', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
});

fastify.post('/register', async (request, reply) => {
  const { username, email, password } = request.body;

  try {
    const [existingUser] = await pool.query('SELECT * FROM Users WHERE username = ? OR email = ?', [username, email]);
    if (existingUser.length > 0) {
      reply.code(400).send({ message: 'Username or email already exists' });
      return;
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.query('INSERT INTO Users (username, email, password) VALUES (?, ?, ?)', [username, email, hashedPassword]);

    const token = jwt.sign({ userId: result.insertId }, 'your_secret_key', { expiresIn: '1h' });

    reply.send({ token });
  } catch (err) {
    console.error('Error registering user:', err);
    reply.code(500).send({ message: 'Internal server error' });
  }
});

fastify.post('/login', async (request, reply) => {
  const { username, email, password } = request.body;

  try {
    const [rows] = await pool.query('SELECT * FROM Users WHERE username = ? OR email = ?', [username, email]);
    if (rows.length === 0) {
      reply.code(401).send({ message: 'Invalid username or email' });
      return;
    }

    const user = rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      reply.code(401).send({ message: 'Invalid password' });
      return;
    }

    const token = jwt.sign({ userId: user.member_id,username: user.username }, 'your_secret_key', { expiresIn: '1h' });

    reply.send({ token,username: user.username,userId: user.member_id });
  } catch (err) {
    console.error('Error logging in:', err);
    reply.code(500).send({ message: 'Internal server error' });
  }
});

fastify.get('/auth/status', async (request, reply) => {
  const authHeader = request.headers.authorization;

  if (!authHeader) {
    return reply.code(401).send({ isLoggedIn: false });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, 'your_secret_key');
    const [rows] = await pool.query('SELECT * FROM Users WHERE member_id = ?', [decoded.userId]);
    if (rows.length === 0) {
      return reply.code(401).send({ isLoggedIn: false });
    }
    const user = rows[0];
    reply.send({
      isLoggedIn: true,
      user: {
        username: user.username,
        email: user.email,
        address: user.address,
        phone_number: user.phone_number,
      }
    });
  } catch (err) {
    console.error('Error verifying token:', err);
    reply.code(500).send({ isLoggedIn: false });
  }
});

fastify.post('/logout', async (request, reply) => {
  // No real logout logic needed for JWT, as it's stateless. The client simply discards the token.
  reply.send({ message: 'Logged out successfully' });
});

fastify.post('/check', async (request, reply) => {
  const { email, username } = request.body;

  // ตรวจสอบว่าอีเมลและชื่อผู้ใช้งานไม่ว่างเปล่า
  if (!email || !username) {
    return reply.status(400).send({ error: 'Email and username are required' });
  }

  try {
    const [emailRows] = await pool.query('SELECT * FROM Users WHERE email = ?', [email]);
    const [usernameRows] = await pool.query('SELECT * FROM Users WHERE username = ?', [username]);

    const emailTaken = emailRows.length > 0;
    const usernameTaken = usernameRows.length > 0;

    reply.send({ emailTaken, usernameTaken });
  } catch (err) {
    console.error('Error checking user data:', err);
    reply.status(500).send({ error: 'Internal server error' });
  }
});

fastify.post('/check-username', async (request, reply) => {
  const { username } = request.body;

  try {
    const [existingUser] = await pool.query('SELECT * FROM Users WHERE username = ?', [username]);
    reply.send({ isTaken: existingUser.length > 0 });
  } catch (err) {
    console.error('Error checking username:', err);
    reply.code(500).send({ message: 'Internal server error' });
  }
});

fastify.post('/check-email', async (request, reply) => {
  const { email } = request.body;

  try {
    const [existingUser] = await pool.query('SELECT * FROM Users WHERE email = ?', [email]);
    reply.send({ isTaken: existingUser.length > 0 });
  } catch (err) {
    console.error('Error checking email:', err);
    reply.code(500).send({ message: 'Internal server error' });
  }
});


fastify.post('/upload', async (request, reply) => {
  if (!request.body || !request.body.imageData) {
    reply.status(400).send('Missing image data');
    return;
  }

  const { imageName, imageData } = request.body;

  try {
    // Insert image data into the database
    const [result] = await pool.query('INSERT INTO Images (ImageName, ImageData) VALUES (?, ?)', [imageName, imageData]);

    reply.status(200).send('Image uploaded successfully');
  } catch (err) {
    console.error('Error uploading image:', err);
    reply.status(500).send('Internal server error');
  }
});



fastify.get('/images', async (request, reply) => {
  try {
    const [images] = await pool.query('SELECT ImageID, ImageName, ImageData, UploadDate FROM Images');
    const imageDetails = images.map(image => ({
      ImageID: image.ImageID,
      ImageName: image.ImageName,
      ImageData: `${image.ImageData}`, // ไม่ต้องใช้ toString('base64')
      UploadDate: image.UploadDate,
    }));
    reply.send(imageDetails);
  } catch (err) {
    console.error('Error fetching images:', err);
    reply.code(500).send({ message: 'Internal server error' });
  }
});

async function checkIfImageUploaded() {
  return new Promise((resolve, reject) => {
    db.query('SELECT COUNT(*) AS imageCount FROM Images', (err, result) => {
      if (err) {
        reject(err);
      } else {
        resolve(result[0].imageCount > 0); // Returns true if there's at least one image uploaded
      }
    });
  });
}

fastify.post('/upload-image', async (request, reply) => {
  console.log('Request body:', request.body);

  const { product_name, description, price, quantity, category, image_base64 } = request.body;

  if (!product_name || !image_base64 || !price || !quantity || !category) {
    reply.status(400).send('Missing required fields');
    return;
  }

  try {
    // Insert image data into the database
    const [result] = await pool.query('INSERT INTO products (product_name, description, price, quantity, category, image_base64) VALUES (?, ?, ?, ?, ?, ?)', [product_name, description, price, quantity, category, image_base64]);


    
    reply.status(200).send('Image uploaded successfully');
  } catch (err) {
    console.error('Error uploading image:', err);
    reply.status(500).send(`Internal server error: ${err.message}`);
  }
});

fastify.get('/products', async (request, reply) => {
  try {
    // Query to fetch all product data from the database
    const [rows] = await pool.query('SELECT product_id, product_name, description, price, quantity, category, image_base64, sales_count FROM products ');
    const productDetails = rows.map(product => ({
      ProductID: product.product_id,
      ProductName: product.product_name,
      ProductDescription: product.description,
      ProductPrice: product.price,
      ProductQuantity: product.quantity,
      ProductCategory: product.category,
      ProductImage: `${product.image_base64}`,
      ProductSaleCount : product.sales_count,
    }));
    reply.send(productDetails);
  } catch (err) {
    console.error('Error fetching products:', err);
    reply.status(500).send(`Internal server error: ${err.message}`);
  }
});

fastify.put('/products/:productId', async (request, reply) => {
  const productId = request.params.productId;
  const { ProductName, ProductDescription, ProductPrice, ProductQuantity, ProductCategory } = request.body;

  try {
    // Update product in the database
    await pool.query('UPDATE products SET product_name = ?, description = ?, price = ?, quantity = ?, category = ? WHERE product_id = ?', 
      [ProductName, ProductDescription, ProductPrice, ProductQuantity, ProductCategory, productId]);

      console.log(`Product with ID ${productId} updated successfully`);

    reply.code(200).send({ message: 'Product updated successfully' });
  } catch (err) {
    console.error('Error updating product:', err);
    reply.code(500).send({ message: 'Internal server error' });
  }
});

fastify.delete('/products/:productId', async (request, reply) => {
  const productId = request.params.productId;

  try {
    // Delete product from the database
    await pool.query('DELETE FROM products WHERE product_id = ?', [productId]);

    // Reorder product ids
    await pool.query('SET @counter = 0');
    await pool.query('UPDATE products SET product_id = @counter := @counter + 1');
    await pool.query('ALTER TABLE products AUTO_INCREMENT = 1');

    reply.code(200).send({ message: 'Product deleted successfully' });
  } catch (err) {
    console.error('Error deleting product:', err);
    reply.code(500).send({ message: 'Internal server error' });
  }
});

fastify.get('/user/:id', async (request, reply) => {
  const { id } = request.params;

  try {
    const [rows] = await pool.query('SELECT * FROM Users WHERE member_id = ?', [id]);
    if (rows.length === 0) {
      reply.status(404).send({ error: 'User not found' });
    } else {
      const user = rows[0];
      // แปลงค่า profileimg เป็นข้อความ (เช่น, base64)
      const profileimgText = user.profileimg.toString('utf8'); // เปลี่ยน 'utf8' เป็น 'base64' หรือรูปแบบที่เหมาะสม
      // สร้าง object ใหม่ที่มีข้อมูลทั้งหมดรวมถึง profileimgText
      const userWithProfileImgText = {
        ...user,
        profileimg: profileimgText
      };
      reply.send(userWithProfileImgText);
    }
  } catch (err) {
    console.error('Error fetching user data:', err);
    reply.status(500).send({ error: 'Internal server error' });
  }
});

fastify.put('/user/:id', async (request, reply) => {
  const { id } = request.params;
  const { name, address, phone_number, profileimg } = request.body;

  // Log the received data to debug
  fastify.log.info('Received data:', { name, address, phone_number, profileimg });

  try {
    // Update the user's information
    const [result] = await pool.query(
      'UPDATE Users SET name = ?, address = ?, phone_number = ?, profileimg = ? WHERE member_id = ?',
      [name, address, phone_number, profileimg, id]
    );

    // Check if the update was successful
    if (result.affectedRows === 0) {
      return reply.status(404).send({ message: 'User not found' });
    }

    // Log the result of the query to debug
    fastify.log.info('Query result:', result);

    reply.send({ message: 'User updated successfully' });
  } catch (err) {
    request.log.error('Error updating user:', err);
    reply.status(500).send({ message: 'Internal server error', error: err.message });
  }
});

fastify.post('/add-to-cart', async (request, reply) => {
  const { memberId, productId, quantity } = request.body;

  // Log the received request body for debugging
  request.log.info(`Received request body: ${JSON.stringify(request.body)}`);

  if (!memberId || !productId ) {
    return reply.status(400).send({ error: 'Missing required fields: memberId, productId, and quantity are required' });
  }

  try {
    // ตรวจสอบว่า connection ถูกใช้ถูกต้อง
    const [rows] = await pool.query(
      'SELECT * FROM Shopping_Cart WHERE member_id = ? AND product_id = ?',
      [memberId, productId]
    );

    if (rows.length > 0) {
      await pool.query(
        'UPDATE Shopping_Cart SET quantity = quantity + ? WHERE member_id = ? AND product_id = ?',
        [quantity, memberId, productId]
      );
    } else {
      await pool.query(
        'INSERT INTO Shopping_Cart (member_id, product_id, quantity) VALUES (?, ?, ?)',
        [memberId, productId, quantity]
      );
    }

    return reply.send({ success: true, message: 'Product added to cart' });
  } catch (err) {
    request.log.error(err);
    return reply.status(500).send({ error: 'Database error' });
  }
});

fastify.get('/cart/:memberId', async (request, reply) => {
  const { memberId } = request.params;

  try {
    const [rows] = await pool.query(
      `SELECT sc.cart_id, sc.quantity, p.product_name, p.description, p.price, p.image_base64, p.quantity, sc.product_id
      FROM Shopping_Cart sc 
      JOIN products p ON sc.product_id = p.product_id 
      WHERE sc.member_id = ?`,
      [memberId]
    );

    const updatedRows = rows.map(row => ({
      ...row,
      image_base64: row.image_base64 ? row.image_base64.toString('utf-8') : null
    }));

    reply.send(updatedRows);
  } catch (err) {
    request.log.error(err);
    reply.status(500).send({ error: 'Database error', details: err.message });
  }
});

fastify.delete('/cart/:memberId/:productId', async (request, reply) => {
  const { memberId, productId } = request.params;

  try {
    await pool.query(
      `DELETE FROM Shopping_Cart WHERE member_id = ? AND product_id = ?`,
      [memberId, productId]
    );
    reply.send({ success: true });
  } catch (err) {
    request.log.error(err);
    reply.status(500).send({ error: 'Database error', details: err.message });
  }
});

fastify.post('/add-to-favorites', async (request, reply) => {
  const { member_id, product_id } = request.body;

  try {
    const [existingFavorite] = await pool.query('SELECT * FROM Favorite_Products WHERE member_id = ? AND product_id = ?', [member_id, product_id]);
    if (existingFavorite.length > 0) {
      reply.code(400).send({ success: false, message: 'Product is already in favorites' });
      return;
    }

    await pool.query('INSERT INTO Favorite_Products (member_id, product_id) VALUES (?, ?)', [member_id, product_id]);

    reply.code(201).send({ success: true, message: 'Product added to favorites' });
  } catch (err) {
    console.error('Error adding product to favorites:', err);
    reply.code(500).send({ success: false, message: 'Internal server error' });
  }
});

fastify.get('/favorites/:member_id', async (request, reply) => {
  const { member_id } = request.params;

  try {
    const [favorites] = await pool.query(`
      SELECT fp.product_id, p.product_name, p.description, p.price, p.image_base64 
      FROM Favorite_Products fp
      JOIN products p ON fp.product_id = p.product_id
      WHERE fp.member_id = ?
    `, [member_id]);

    const favoriteDetails = favorites.map(favorite => ({
      ProductID: favorite.product_id,
      ProductName: favorite.product_name,
      ProductDescription: favorite.description,
      ProductPrice: favorite.price,
      ProductImage: favorite.image_base64 ? favorite.image_base64.toString('utf-8') : null
    }));

    reply.send(favoriteDetails);
  } catch (err) {
    console.error('Error fetching favorites:', err);
    reply.code(500).send({ success: false, message: 'Internal server error' });
  }
});

fastify.delete('/favorites/:member_id/:product_id', async (request, reply) => {
  const { member_id, product_id } = request.params;

  try {
    const [result] = await pool.query('DELETE FROM Favorite_Products WHERE member_id = ? AND product_id = ?', [member_id, product_id]);

    if (result.affectedRows === 0) {
      reply.code(404).send({ success: false, message: 'Favorite not found' });
      return;
    }

    reply.send({ success: true, message: 'Product removed from favorites' });
  } catch (err) {
    console.error('Error removing product from favorites:', err);
    reply.code(500).send({ success: false, message: 'Internal server error' });
  }
});

fastify.post('/order', async (request, reply) => {
  const { memberId, cartItems, totalAmount } = request.body;

  console.log('Received request:', request.body); // Log request body

  try {
    // Insert order into orders table
    const orderQuery = 'INSERT INTO orders (member_id, total_amount) VALUES (?, ?)';
    const [orderResult] = await pool.query(orderQuery, [memberId, totalAmount]);
    const orderId = orderResult.insertId;
    console.log('Order Result:', orderResult); // Log order result

    // Insert each item in the order_items table
    const orderItemsQuery = 'INSERT INTO order_items (order_id, product_id, quantity, price) VALUES ?';
    const orderItemsData = cartItems.map(item => [orderId, item.product_id, item.quantity, item.price]);

    await pool.query(orderItemsQuery, [orderItemsData]);

    reply.status(200).send('Order placed successfully');
  } catch (err) {
    console.error('Error placing order:', err);
    reply.status(500).send({ message: 'Internal server error', error: err });
  }
});

fastify.get('/orders/:memberId', async (request, reply) => {
  const memberId = request.params.memberId;
  try {
    const ordersQuery = 'SELECT * FROM orders WHERE member_id = ?';
    const [orders] = await pool.query(ordersQuery, [memberId]);
    
    reply.status(200).send(orders);
  } catch (err) {
    console.error('Error fetching orders:', err);
    reply.status(500).send({ message: 'Internal server error' });
  }
});

fastify.get('/order-items/:orderId', async (request, reply) => {
  const orderId = request.params.orderId;
  if (!orderId) {
    console.error('Order ID is required');
    return reply.status(400).send('Order ID is required');
  }
  try {
    const query = `
      SELECT 
        oi.order_item_id, 
        oi.quantity, 
        oi.price, 
        p.product_id, 
        p.product_name, 
        p.description, 
        p.price AS product_price, 
        p.quantity AS product_quantity, 
        p.category, 
        CAST(p.image_base64 AS CHAR) AS image_base64, 
        p.sales_count
      FROM order_items oi
      JOIN products p ON oi.product_id = p.product_id
      WHERE oi.order_id = ?
    `;
    const [items] = await pool.query(query, [orderId]); // Use 'pool' instead of 'db'
    if (!items.length) {
      console.warn('No items found for order ID:', orderId);
    }
    reply.status(200).send(items); // Use 'reply.send' instead of 'res.json'
  } catch (error) {
    console.error('Error retrieving order items:', error.message);
    reply.status(500).send('Error retrieving order items'); // Use 'reply.send' instead of 'res.json'
  }
});


// Start the server
const start = async () => {
  try {
    await fastify.listen(3000);
    console.log('Server is running on http://localhost:3000');
  } catch (err) {
    console.error('Error starting server:', err);
    process.exit(1);
  }
};

start();