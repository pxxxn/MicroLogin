require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const User = require('./models/User');

const app = express();
app.use(express.json());

// Conexión a MongoDB Atlas
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
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

    // Verificar si usuario existe
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(409).json({ message: 'El usuario ya existe' });
    }

    // Encriptar password y respuesta secreta
    const passwordHash = await bcrypt.hash(password, 10);
    const secretAnswerHash = await bcrypt.hash(secretAnswer, 10);

    // Crear y guardar usuario
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

// Puerto
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor escuchando en puerto ${PORT}`);
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Verifica que los datos estén completos
    if (!username || !password) {
      return res.status(400).json({ message: 'Usuario y contraseña requeridos' });
    }

    // Buscar usuario
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: 'Usuario no encontrado' });
    }

    // Comparar contraseñas
    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ message: 'Contraseña incorrecta' });
    }

    // Login exitoso
    res.status(200).json({ message: 'Login exitoso' });

  } catch (error) {
    console.error('Error en /login:', error);
    res.status(500).json({ message: 'Error del servidor' });
  }
});

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

    // Regresamos solo la pregunta secreta (NO la respuesta)
    res.status(200).json({ secretQuestion: user.secretQuestion });

  } catch (error) {
    console.error('Error en /recover-question:', error);
    res.status(500).json({ message: 'Error del servidor' });
  }
});

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

    // Compara la respuesta secreta
    const isAnswerCorrect = await bcrypt.compare(secretAnswer, user.secretAnswerHash);
    if (!isAnswerCorrect) {
      return res.status(401).json({ message: 'Respuesta secreta incorrecta' });
    }

    // Si es correcta, actualiza la contraseña
    const newPasswordHash = await bcrypt.hash(newPassword, 10);
    user.passwordHash = newPasswordHash;
    await user.save();

    res.status(200).json({ message: 'Contraseña actualizada correctamente' });

  } catch (error) {
    console.error('Error en /recover-password:', error);
    res.status(500).json({ message: 'Error del servidor' });
  }
});
