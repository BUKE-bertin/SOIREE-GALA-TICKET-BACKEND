import express from 'express';
import cors from 'cors';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
const app = express();

app.use(cors());
app.use(express.json());

app.post('/api/orders', async (req, res) => {
  try {
    const { nom, prenom, email, cin, idAsebem, pack, nombrePersonnes, beneficiaires } = req.body;

    const order = await prisma.order.create({
      data: {
        nom,
        prenom,
        email,
        cin,
        idAsebem,
        pack,
        nombrePersonnes,
        beneficiaires: {
          create: beneficiaires || [],
        },
      },
    });

    res.status(201).json({ success: true, orderId: order.id });
  } catch (error) {
    console.error('Error creating order:', error);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

// ADMIN ROUTES
const JWT_SECRET = process.env.JWT_SECRET || "gala_asebem_super_secret_2026";

app.post('/api/admin/signup', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const existingAdmin = await prisma.admin.findUnique({ where: { username } });
    if (existingAdmin) {
      return res.status(400).json({ error: 'Cet utilisateur existe déjà' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newAdmin = await prisma.admin.create({
      data: {
        username,
        password: hashedPassword,
      }
    });

    res.status(201).json({ success: true, message: 'Administrateur créé avec succès' });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la création du compte' });
  }
});

app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const admin = await prisma.admin.findUnique({ where: { username } });
    if (!admin) {
      return res.status(401).json({ error: 'Identifiants invalides' });
    }

    const isValid = await bcrypt.compare(password, admin.password);
    if (!isValid) {
      return res.status(401).json({ error: 'Identifiants invalides' });
    }

    const token = jwt.sign({ adminId: admin.id, username: admin.username }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la connexion' });
  }
});

// Middleware for Admin Auth
const requireAdmin = (req: express.Request, res: express.Response, next: express.NextFunction): void => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Non autorisé' });
    return;
  }
  
  const token = authHeader.split(' ')[1];
  try {
    jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    res.status(401).json({ error: 'Session expirée ou invalide' });
  }
};

app.get('/api/admin/orders', requireAdmin, async (req, res) => {
  try {
    const orders = await prisma.order.findMany({
      include: { beneficiaires: true },
      orderBy: { createdAt: 'desc' }
    });
    res.json(orders);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

app.patch('/api/admin/orders/:id/status', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    const updatedOrder = await prisma.order.update({
      where: { id: String(id) },
      data: { status: String(status) }
    });
    res.json(updatedOrder);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update order' });
  }
});

if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

export default app;
