require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

app.get('/', (req, res) => { res.send('YAMA API is Live 🟢'); });

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(400).json({ error: "User not found" });
  const validPass = await bcrypt.compare(password, user.password);
  if (!validPass) return res.status(400).json({ error: "Invalid password" });
  const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET);
  res.json({ token });
});

app.post('/api/auth/register', async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const user = await prisma.user.create({ data: { email, password: hashedPassword } });
    res.json(user);
  } catch (e) { res.status(400).json({ error: "User already exists" }); }
});

app.get('/api/movies', async (req, res) => {
  const movies = await prisma.movie.findMany({ orderBy: { createdAt: 'desc' } });
  res.json(movies);
});

app.post('/api/movies', authenticateToken, async (req, res) => {
  try {
    const movie = await prisma.movie.create({ data: req.body });
    res.json(movie);
  } catch (e) { res.status(500).json({ error: "Failed to save movie" }); }
});

app.put('/api/movies/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const movie = await prisma.movie.update({ where: { id: parseInt(id) }, data: req.body });
    res.json(movie);
  } catch (e) { res.status(500).json({ error: "Failed to update movie" }); }
});

app.delete('/api/movies/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    await prisma.movie.delete({ where: { id: parseInt(id) } });
    res.json({ message: "Deleted" });
  } catch (e) { res.status(500).json({ error: "Failed to delete" }); }
});

app.listen(PORT, () => { console.log(`Server running on port ${PORT}`); });