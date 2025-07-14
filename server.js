require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cors = require('cors'); 

const User = require('./models/User');

const app = express();
app.use(cors()); 
app.use(express.json());

// Conexión a MongoDB Atlas
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Conectado a MongoDB Atlas'))
  .catch((error) => console.error('Error al conectar a MongoDB', error));

// Ruta de prueba
app.get('/', (req, res) => {
  res.send('Microservicio funcionando');
});

// Ruta para registrar usuario
app.post('/register', async (req, res) => {
  try {
    const { username, password, secretQuestion, secretAnswer } = req.body;

    if (!username || !password || !secretQuestion || !secretAnswer) {
      return res.status(400).json({ message: 'Faltan datos obligatorios' });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(409).json({ message: 'El usuario ya existe' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const secretAnswerHash = await bcrypt.hash(secretAnswer, 10);

    const newUser = new User({
      username,
      passwordHash,
      secretQuestion,
      secretAnswerHash
    });

    await newUser.save();

    res.status(201).json({ message: 'Usuario registrado exitosamente' });
  } catch (error) {
    console.error('Error en /register:', error);
    res.status(500).json({ message: 'Error del servidor' });
  }
});

// Ruta para login
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: 'Usuario y contraseña requeridos' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: 'Usuario no encontrado' });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ message: 'Contraseña incorrecta' });
    }

    res.status(200).json({ message: 'Login exitoso' });
  } catch (error) {
    console.error('Error en /login:', error);
    res.status(500).json({ message: 'Error del servidor' });
  }
});

// Ruta para obtener pregunta secreta
app.post('/recover-question', async (req, res) => {
  try {
    const { username } = req.body;

    if (!username) {
      return res.status(400).json({ message: 'Username requerido' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    res.status(200).json({ secretQuestion: user.secretQuestion });
  } catch (error) {
    console.error('Error en /recover-question:', error);
    res.status(500).json({ message: 'Error del servidor' });
  }
});

// Ruta para recuperar contraseña
app.post('/recover-password', async (req, res) => {
  try {
    const { username, secretAnswer, newPassword } = req.body;

    if (!username || !secretAnswer || !newPassword) {
      return res.status(400).json({ message: 'Faltan datos' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    const isAnswerCorrect = await bcrypt.compare(secretAnswer, user.secretAnswerHash);
    if (!isAnswerCorrect) {
      return res.status(401).json({ message: 'Respuesta secreta incorrecta' });
    }

    const newPasswordHash = await bcrypt.hash(newPassword, 10);
    user.passwordHash = newPasswordHash;
    await user.save();

    res.status(200).json({ message: 'Contraseña actualizada correctamente' });
  } catch (error) {
    console.error('Error en /recover-password:', error);
    res.status(500).json({ message: 'Error del servidor' });
  }
});

// Puerto
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor escuchando en puerto ${PORT}`);
});
