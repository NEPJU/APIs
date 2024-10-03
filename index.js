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

    // ตรวจสอบบทบาทของผู้ใช้ (role หรือ is_admin)
    const role = user.role || (user.is_admin ? 'admin' : 'user'); // ใช้ role ถ้ามี หรือ is_admin

    const token = jwt.sign(
      { userId: user.member_id, username: user.username, role }, // เพิ่ม role ลงใน payload ของ token
      'your_secret_key',
      { expiresIn: '1h' }
    );

    reply.send({
      token,
      username: user.username,
      userId: user.member_id,
      role // ส่งบทบาทของผู้ใช้กลับไปด้วย
    });
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
  const { product_name, description, price, quantity, category, images_base64 } = request.body;

  if (!product_name || !images_base64 || !price || !quantity || !category) {
    reply.status(400).send('Missing required fields');
    return;
  }

  try {
    // Insert product data into the products table including images
    await pool.query(
      'INSERT INTO products (product_name, description, price, quantity, category, images_base64) VALUES (?, ?, ?, ?, ?, ?)',
      [product_name, description, price, quantity, category, JSON.stringify(images_base64)]
    );

    // Reorder the product IDs
    const [products] = await pool.query('SELECT product_id FROM products ORDER BY product_id ASC');

    // Update product IDs sequentially
    for (let i = 0; i < products.length; i++) {
      const oldProductId = products[i].product_id;
      const newProductId = i + 1;

      // Update the product ID in the products table
      await pool.query('UPDATE products SET product_id = ? WHERE product_id = ?', [newProductId, oldProductId]);

      // Update foreign key references in related tables
      await pool.query('UPDATE order_items SET product_id = ? WHERE product_id = ?', [newProductId, oldProductId]);
      await pool.query('UPDATE favorite_products SET product_id = ? WHERE product_id = ?', [newProductId, oldProductId]);
      await pool.query('UPDATE shopping_cart SET product_id = ? WHERE product_id = ?', [newProductId, oldProductId]);
    }

    reply.status(200).send('Product and images uploaded successfully and IDs reordered');
  } catch (err) {
    console.error('Error uploading product:', err);
    reply.status(500).send(`Internal server error: ${err.message}`);
  }
});


fastify.get('/products', async (request, reply) => {
  try {
    const [products] = await pool.query(`
      SELECT 
        product_id AS ProductID,
        product_name AS ProductName,
        description AS ProductDescription,
        price AS ProductPrice,
        quantity AS ProductQuantity,
        category AS ProductCategory,
        sales_count AS ProductSaleCount,
        COALESCE((
          SELECT AVG(rating) 
          FROM product_reviews 
          WHERE product_id = products.product_id
        ), 0) AS averageRating,
        images_base64 AS ProductImage
      FROM products
    `);

    // Convert images_base64 from JSON String to Array
    products.forEach(product => {
      if (product.ProductImage) {
        try {
          product.images = JSON.parse(product.ProductImage);
        } catch (e) {
          console.error("Error parsing ProductImage JSON:", e);
          product.images = [];
        }
      } else {
        product.images = [];
      }
    });

    reply.send(products);
  } catch (err) {
    console.error('Error fetching products:', err);
    reply.status(500).send({ message: 'Internal server error' });
  }
});




fastify.put('/products/:productId', async (request, reply) => {
  const productId = request.params.productId;
  const {
    product_name,
    description,
    price,
    quantity,
    category
  } = request.body;

  // Check if any of the required fields are missing
  if (!product_name || !description || !price || !quantity || !category) {
    reply.code(400).send({ message: 'All fields are required' });
    return;
  }

  try {
    // Update product in the database
    await pool.query(
      'UPDATE products SET product_name = ?, description = ?, price = ?, quantity = ?, category = ? WHERE product_id = ?',
      [product_name, description, price, quantity, category, productId]
    );

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
    // Start a transaction to ensure atomicity
    await pool.query('START TRANSACTION');

    // Disable foreign key checks to allow ID reordering
    await pool.query('SET FOREIGN_KEY_CHECKS = 0');

    // Delete from related tables referencing the product_id
    await pool.query('DELETE FROM order_items WHERE product_id = ?', [productId]);
    await pool.query('DELETE FROM favorite_products WHERE product_id = ?', [productId]);
    await pool.query('DELETE FROM shopping_cart WHERE product_id = ?', [productId]);

    // Delete the product itself from the products table
    await pool.query('DELETE FROM products WHERE product_id = ?', [productId]);

    // Reorder the product IDs
    const [products] = await pool.query('SELECT product_id FROM products ORDER BY product_id ASC');

    // Update product IDs sequentially
    for (let i = 0; i < products.length; i++) {
      const oldProductId = products[i].product_id;
      const newProductId = i + 1;

      // Update the product ID in the products table
      await pool.query('UPDATE products SET product_id = ? WHERE product_id = ?', [newProductId, oldProductId]);

      // Update foreign key references in related tables
      await pool.query('UPDATE order_items SET product_id = ? WHERE product_id = ?', [newProductId, oldProductId]);
      await pool.query('UPDATE favorite_products SET product_id = ? WHERE product_id = ?', [newProductId, oldProductId]);
      await pool.query('UPDATE shopping_cart SET product_id = ? WHERE product_id = ?', [newProductId, oldProductId]);
    }

    // Re-enable foreign key checks
    await pool.query('SET FOREIGN_KEY_CHECKS = 1');

    // Commit the transaction
    await pool.query('COMMIT');

    reply.code(200).send({ message: 'Product and related records deleted and IDs reordered successfully' });
  } catch (err) {
    // Rollback the transaction in case of an error
    await pool.query('ROLLBACK');

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

// fastify.post('/add-to-cart', async (request, reply) => {
//   const { memberId, productId, quantity } = request.body;

//   // Log the received request body for debugging
//   request.log.info(`Received request body: ${JSON.stringify(request.body)}`);

//   if (!memberId || !productId ) {
//     return reply.status(400).send({ error: 'Missing required fields: memberId, productId, and quantity are required' });
//   }

//   try {
//     // ตรวจสอบว่า connection ถูกใช้ถูกต้อง
//     const [rows] = await pool.query(
//       'SELECT * FROM Shopping_Cart WHERE member_id = ? AND product_id = ?',
//       [memberId, productId]
//     );

//     if (rows.length > 0) {
//       await pool.query(
//         'UPDATE Shopping_Cart SET quantity = quantity + ? WHERE member_id = ? AND product_id = ?',
//         [quantity, memberId, productId]
//       );
//     } else {
//       await pool.query(
//         'INSERT INTO Shopping_Cart (member_id, product_id, quantity) VALUES (?, ?, ?)',
//         [memberId, productId, quantity]
//       );
//     }

//     return reply.send({ success: true, message: 'Product added to cart' });
//   } catch (err) {
//     request.log.error(err);
//     return reply.status(500).send({ error: 'Database error' });
//   }
// });

// fastify.post('/add-to-cart', async (request, reply) => {
//   const { memberId, productId, quantity } = request.body;

//   if (!memberId || !productId) {
//     return reply.status(400).send({ error: 'Missing required fields: memberId, productId, and quantity are required' });
//   }

//   try {
//     // ตรวจสอบว่า connection ถูกใช้ถูกต้อง
//     const [rows] = await pool.query(
//       'SELECT * FROM Shopping_Cart WHERE member_id = ? AND product_id = ?',
//       [memberId, productId]
//     );

//     if (rows.length > 0) {
//       await pool.query(
//         'UPDATE Shopping_Cart SET quantity = quantity + ? WHERE member_id = ? AND product_id = ?',
//         [quantity, memberId, productId]
//       );
//     } else {
//       await pool.query(
//         'INSERT INTO Shopping_Cart (member_id, product_id, quantity) VALUES (?, ?, ?)',
//         [memberId, productId, quantity]
//       );
//     }

//     // ดึงข้อมูลสินค้าในตะกร้าของผู้ใช้ทั้งหมดกลับมา
//     const [updatedCart] = await pool.query(
//       `SELECT sc.cart_id, sc.quantity, p.product_name, p.description, p.price, p.images_base64, p.quantity, sc.product_id
//       FROM Shopping_Cart sc 
//       JOIN products p ON sc.product_id = p.product_id 
//       WHERE sc.member_id = ?`,
//       [memberId]
//     );

//     reply.send({ success: true, message: 'Product added to cart', cartItems: updatedCart });
//   } catch (err) {
//     request.log.error(err);
//     return reply.status(500).send({ error: 'Database error' });
//   }
// });

fastify.post('/add-to-cart', async (request, reply) => {
  const { memberId, productId, quantity } = request.body;

  if (!memberId || !productId) {
    return reply.status(400).send({ error: 'Missing required fields: memberId, productId, and quantity are required' });
  }

  try {
    // ตรวจสอบว่ามีสินค้าชิ้นนั้นๆ ในตะกร้าอยู่หรือไม่
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

    // ดึงข้อมูลสินค้าในตะกร้าของผู้ใช้ทั้งหมดกลับมา
    const [updatedCart] = await pool.query(
      `SELECT sc.cart_id, sc.quantity AS quantityInCart, p.product_name, p.description, p.price, p.images_base64, p.quantity, sc.product_id
      FROM Shopping_Cart sc 
      JOIN products p ON sc.product_id = p.product_id 
      WHERE sc.member_id = ?`,
      [memberId]
    );

    reply.send({ success: true, message: 'Product added to cart', cartItems: updatedCart });
  } catch (err) {
    request.log.error(err);
    return reply.status(500).send({ error: 'Database error' });
  }
});



fastify.get('/cart/:memberId', async (request, reply) => {
  const { memberId } = request.params;

  if (!memberId) {
    return reply.status(400).send({ error: 'Missing required field: memberId' });
  }

  try {
    const [cartItems] = await pool.query(
      `SELECT sc.cart_id, sc.quantity AS quantityInCart, p.product_name, p.description, p.price, p.images_base64, p.quantity AS productStock, sc.product_id
      FROM Shopping_Cart sc 
      JOIN products p ON sc.product_id = p.product_id 
      WHERE sc.member_id = ?`,
      [memberId]
    );

    reply.send(cartItems);
  } catch (err) {
    request.log.error(err);
    return reply.status(500).send({ error: 'Database error' });
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

  if (!member_id || !product_id) {
    reply.code(400).send({ success: false, message: 'Missing member_id or product_id' });
    return;
  }

  try {
    const [existingFavorite] = await pool.query(
      'SELECT * FROM Favorite_Products WHERE member_id = ? AND product_id = ?',
      [member_id, product_id]
    );
    if (existingFavorite.length > 0) {
      reply.code(400).send({ success: false, message: 'Product is already in favorites' });
      return;
    }

    await pool.query(
      'INSERT INTO Favorite_Products (member_id, product_id) VALUES (?, ?)',
      [member_id, product_id]
    );

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
      SELECT fp.product_id, p.product_name, p.description, p.price, p.images_base64 
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
        CAST(p.images_base64 AS CHAR) AS image_base64, 
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

fastify.put('/orders/:orderId/status', async (request, reply) => {
  const orderId = request.params.orderId;
  const { status, tracking_number, payment_image_base64 } = request.body;

  console.log('Received data:', { orderId, status, tracking_number, payment_image_base64 });

  if (!orderId || !status) {
    return reply.status(400).send({ message: 'Order ID and status are required' });
  }

  try {
    // เริ่ม query ด้วยการอัปเดต status เท่านั้น
    let query = `UPDATE orders SET status = ?`;
    const params = [status];

    // เพิ่มเงื่อนไขเฉพาะเมื่อมีการส่งค่า tracking_number
    if (tracking_number !== undefined) {
      query += `, tracking_number = ?`;
      params.push(tracking_number);
    }

    // เพิ่มเงื่อนไขเฉพาะเมื่อมีการส่งค่า payment_image_base64
    if (payment_image_base64 !== undefined) {
      query += `, payment_image_base64 = ?`;
      params.push(payment_image_base64);
    }

    query += ` WHERE order_id = ?`;
    params.push(orderId);

    console.log('Executing query with:', { query, params });
    const [result] = await pool.query(query, params);

    if (result.affectedRows === 0) {
      console.log('No rows affected, order not found.');
      return reply.status(404).send({ message: 'Order not found' });
    }

    reply.status(200).send({ message: 'Order updated successfully' });
  } catch (error) {
    console.error('Error updating order:', error.message);
    reply.status(500).send({ message: 'Internal server error' });
  }
});


fastify.post('/orders/:orderId/upload', async (request, reply) => {
  const orderId = request.params.orderId;
  const data = await request.file();

  if (!data) {
    return reply.status(400).send({ success: false, message: 'No file uploaded' });
  }

  try {
    const chunks = [];
    data.file.on('data', chunk => chunks.push(chunk));
    data.file.on('end', async () => {
      const fileBuffer = Buffer.concat(chunks);
      const base64Image = `data:${data.mimetype};base64,${fileBuffer.toString('base64')}`;

      // Update the orders table with the base64 image string
      const query = 'UPDATE orders SET payment_image_base64 = ? WHERE order_id = ?';
      const [result] = await pool.query(query, [base64Image, orderId]);

      if (result.affectedRows > 0) {
        reply.status(200).send({ success: true, message: 'File uploaded successfully', imageUrl: base64Image });
      } else {
        reply.status(400).send({ success: false, message: 'Order not found or no changes made' });
      }
    });
  } catch (err) {
    console.error('Error saving file info to database:', err);
    reply.status(500).send({ success: false, message: 'Internal server error' });
  }
});


fastify.get('/admin/orders', async (request, reply) => {
  try {
    const query = `
      SELECT 
        orders.*, 
        users.name AS user_name, 
        users.email AS user_email, 
        users.address AS user_address, 
        users.profileimg AS user_profileimg,
        users.phone_number AS user_phone
      FROM orders
      INNER JOIN users ON orders.member_id = users.member_id
      WHERE status = 'Waiting' OR status = 'Shipped' OR status = 'Delivered' OR status = 'Cancelled'
    `;
    const [orders] = await pool.query(query);

    // แปลงข้อมูลโปรไฟล์รูปภาพ (เช่น base64)
    const ordersWithProfileImg = orders.map(order => ({
      ...order,
      user_profileimg: order.user_profileimg ? order.user_profileimg.toString('utf8') : null
    }));
    
    reply.status(200).send(ordersWithProfileImg);
  } catch (err) {
    console.error('Error fetching orders:', err);
    reply.status(500).send({ message: 'Internal server error' });
  }
});


fastify.put('/orders/:orderId/cancel-order', async (request, reply) => {
  const orderId = request.params.orderId;

  if (!orderId) {
    return reply.status(400).send({ message: 'Order ID is required' });
  }

  try {
    // Update the order status to 'Cancelled'
    const query = 'UPDATE orders SET status = ? WHERE order_id = ?';
    const [result] = await pool.query(query, ['Cancelled', orderId]);

    if (result.affectedRows === 0) {
      return reply.status(404).send({ message: 'Order not found' });
    }

    reply.status(200).send({ message: 'Order cancelled successfully' });
  } catch (error) {
    console.error('Error cancelling order:', error.message);
    reply.status(500).send({ message: 'Internal server error' });
  }
});

fastify.put('/orders/:orderId/confirm-payment', async (request, reply) => {
  const orderId = request.params.orderId;
  const { status } = request.body;

  if (!orderId || !status) {
    return reply.status(400).send({ message: 'Order ID and status are required' });
  }

  try {
    // Start a transaction to ensure atomicity
    await pool.query('START TRANSACTION');

    // Update the order status
    const [orderResult] = await pool.query('UPDATE orders SET status = ? WHERE order_id = ?', [status, orderId]);

    if (orderResult.affectedRows === 0) {
      await pool.query('ROLLBACK');
      return reply.status(404).send({ message: 'Order not found' });
    }

    // Fetch order details for logging
    const [order] = await pool.query('SELECT * FROM orders WHERE order_id = ?', [orderId]);
    const [orderItems] = await pool.query(`
      SELECT 
        oi.*, 
        p.product_name, 
        p.category 
      FROM order_items oi
      JOIN products p ON oi.product_id = p.product_id
      WHERE oi.order_id = ?`, 
      [orderId]
    );

    // Log each item in the sales_summary table and update the product's quantity and sales count
    for (const item of orderItems) {
      // Update the product quantity and sales count
      const updateProductQuery = `
        UPDATE products 
        SET 
          quantity = quantity - ?, 
          sales_count = sales_count + ? 
        WHERE product_id = ?
      `;
      await pool.query(updateProductQuery, [item.quantity, item.quantity, item.product_id]);

      // Insert into sales_summary
      await pool.query(
        'INSERT INTO sales_summary (order_id, member_id, product_id, product_name, product_category, quantity, price, total_price, order_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [
          orderId,
          order[0].member_id,
          item.product_id,
          item.product_name,
          item.category,
          item.quantity,
          item.price,
          item.quantity * item.price,
          order[0].order_date
        ]
      );
    }

    // Commit the transaction
    await pool.query('COMMIT');

    reply.status(200).send({ message: 'Order confirmed, product quantities updated, and sales logged successfully.' });
  } catch (error) {
    // Rollback in case of error
    await pool.query('ROLLBACK');
    reply.status(500).send({ message: 'Internal server error' });
  }
});




// fastify.put('/orders/:orderId/add-tracking', async (request, reply) => {
//   const orderId = request.params.orderId;
//   const { tracking_number } = request.body;

//   if (!orderId || !tracking_number) {
//     return reply.status(400).send({ message: 'Order ID and tracking number are required' });
//   }

//   try {
//     const query = 'UPDATE orders SET tracking_number = ? WHERE order_id = ? AND status = "Shipped"';
//     const [result] = await pool.query(query, [tracking_number, orderId]);

//     if (result.affectedRows === 0) {
//       return reply.status(404).send({ message: 'Order not found or not in Shipped status' });
//     }

//     reply.status(200).send({ message: 'Tracking number updated successfully' });
//   } catch (error) {
//     console.error('Error updating tracking number:', error.message);
//     reply.status(500).send({ message: 'Internal server error' });
//   }
// });

fastify.put('/orders/:orderId/add-tracking', async (request, reply) => {
  const orderId = request.params.orderId;
  const { tracking_number, carrier_name } = request.body;

  // ตรวจสอบว่าข้อมูล carrier_name เป็น object และดึงค่า value
  const carrierValue = carrier_name && carrier_name.value ? carrier_name.value : carrier_name;

  // เพิ่มบรรทัดนี้เพื่อตรวจสอบข้อมูลที่ได้รับ
  console.log('Received tracking info:', { tracking_number, carrier_name: carrierValue });

  if (!orderId || !tracking_number || !carrierValue) {
    return reply.status(400).send({ message: 'Order ID, tracking number, and carrier name are required' });
  }

  try {
    const query = 'UPDATE orders SET tracking_number = ?, carrier_name = ? WHERE order_id = ? AND status = "Shipped"';
    const [result] = await pool.query(query, [tracking_number, carrierValue, orderId]);

    if (result.affectedRows === 0) {
      return reply.status(404).send({ message: 'Order not found or not in Shipped status' });
    }

    reply.status(200).send({ message: 'Tracking number and carrier name updated successfully' });
  } catch (error) {
    console.error('Error updating tracking number:', error.message);
    reply.status(500).send({ message: 'Internal server error' });
  }
});

fastify.get('/dashboard/sales-summary', async (request, reply) => {
  const { date, start_date, end_date } = request.query;

  let query, totalSalesQuery, salesOverTimeQuery;
  let queryParams = [];

  if (date) {
    // Specific day query
    query = `
      SELECT product_name, SUM(quantity) AS total_quantity, SUM(total_price) AS total_revenue, DATE(order_date) as sale_date
      FROM sales_summary
      WHERE DATE(order_date) = ?
      GROUP BY product_name, sale_date
    `;

    totalSalesQuery = `
      SELECT SUM(total_price) AS total_sales
      FROM sales_summary
      WHERE DATE(order_date) = ?
    `;

    salesOverTimeQuery = `
      SELECT DATE(order_date) AS sale_date, SUM(total_price) AS total_revenue
      FROM sales_summary
      WHERE DATE(order_date) = ?
      GROUP BY DATE(order_date)
    `;

    queryParams = [date];

  } else if (start_date && end_date) {
    // Date range query
    query = `
      SELECT product_name, SUM(quantity) AS total_quantity, SUM(total_price) AS total_revenue, DATE(order_date) as sale_date
      FROM sales_summary
      WHERE DATE(order_date) BETWEEN ? AND ?
      GROUP BY product_name, sale_date
    `;

    totalSalesQuery = `
      SELECT SUM(total_price) AS total_sales
      FROM sales_summary
      WHERE DATE(order_date) BETWEEN ? AND ?
    `;

    salesOverTimeQuery = `
      SELECT DATE(order_date) AS sale_date, SUM(total_price) AS total_revenue
      FROM sales_summary
      WHERE DATE(order_date) BETWEEN ? AND ?
      GROUP BY DATE(order_date)
    `;

    queryParams = [start_date, end_date];
  }

  try {
    const [salesData] = await pool.query(query, queryParams);
    const [totalSalesData] = await pool.query(totalSalesQuery, queryParams);
    const [salesOverTimeData] = await pool.query(salesOverTimeQuery, queryParams);

    const totalSales = totalSalesData[0]?.total_sales || 0;
    const topProducts = salesData.map(item => ({
      product_name: item.product_name,
      total_quantity: item.total_quantity,
      total_revenue: item.total_revenue,
      sale_date: item.sale_date  // Include sale_date here
    }));

    reply.send({ 
      total_sales: totalSales, 
      top_products: topProducts,
      sales_over_time: salesOverTimeData
    });
  } catch (error) {
    console.error("Database query failed:", error);
    return reply.status(500).send({ message: 'Internal server error', error: error.message });
  }
});


// เพิ่มคะแนนดาว
fastify.post('/product-ratings', async (req, res) => {
  const { productId, memberId, rating } = req.body;

  if (!productId || !memberId || !rating) {
    return res.status(400).send({ success: false, message: 'Invalid input data' });
  }

  try {
    const [result] = await pool.query(
      'INSERT INTO product_reviews (product_id, member_id, rating) VALUES (?, ?, ?)',
      [productId, memberId, rating]
    );
    res.status(201).send({ success: true, ratingId: result.insertId });
  } catch (error) {
    console.error('Error adding rating:', error.message, error.stack);
    res.status(500).send({ success: false, message: 'Failed to add rating' });
  }
});

// เพิ่มความคิดเห็นและคะแนน
fastify.post('/product-reviews', async (req, res) => {
  const { productId, memberId, review, rating } = req.body;

  if (!productId || !memberId || !review || !rating) {
    return res.status(400).send({ success: false, message: 'Invalid input data' });
  }

  try {
    const [result] = await pool.query(
      'INSERT INTO product_reviews (product_id, member_id, review, rating) VALUES (?, ?, ?, ?)',
      [productId, memberId, review, rating]
    );
    res.status(201).send({ success: true, reviewId: result.insertId });
  } catch (error) {
    console.error('Error adding review:', error.message, error.stack);
    res.status(500).send({ success: false, message: 'Failed to add review' });
  }
});

fastify.get('/product-reviews/:productId', async (req, res) => {
  const { productId } = req.params;

  try {
    const query = `
      SELECT pr.*, u.username, CAST(u.profileimg AS CHAR) AS profileimg 
      FROM product_reviews pr 
      JOIN users u ON pr.member_id = u.member_id 
      WHERE pr.product_id = ?
    `;

    const [reviews] = await pool.query(query, [productId]);

    // ข้อมูล profileimg ถูกเก็บในรูปแบบ Base64 แล้ว ดังนั้นสามารถส่งข้อมูลตรงๆ กลับไปได้เลย
    res.send(reviews);
  } catch (error) {
    console.error('Error fetching reviews:', error.message, error.stack);
    res.status(500).send({ success: false, message: 'Failed to fetch reviews' });
  }
});

fastify.delete('/product-reviews/:reviewId', async (req, res) => {
  const { reviewId } = req.params;

  try {
    await pool.query('DELETE FROM product_reviews WHERE review_id = ?', [reviewId]);
    res.send({ success: true, message: 'Review deleted successfully' });
  } catch (error) {
    console.error('Error deleting review:', error.message, error.stack);
    res.status(500).send({ success: false, message: 'Failed to delete review' });
  }
});

fastify.get('/products/:productId', async (request, reply) => {
  const { productId } = request.params;

  try {
    // Fetch product details
    const [products] = await pool.query(`
      SELECT 
        p.product_id, p.product_name, p.description, p.price, p.quantity, p.category, p.images_base64
      FROM products p
      WHERE p.product_id = ?
    `, [productId]);

    if (products.length === 0) {
      return reply.status(404).send({ message: 'Product not found' });
    }

    const product = products[0];

    reply.send(product);
  } catch (err) {
    console.error('Error fetching product:', err);
    reply.status(500).send({ message: 'Internal server error' });
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
}

start();