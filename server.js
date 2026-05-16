const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'kanban_secret_dev_2024';

// Middlewares
app.use(cors());
app.use(express.json());

// File Persistence Helpers
const USERS_FILE = path.join(__dirname, 'users.json');
const TASKS_FILE = path.join(__dirname, 'tasks.json');

const initFiles = () => {
  if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify([]));
  if (!fs.existsSync(TASKS_FILE)) fs.writeFileSync(TASKS_FILE, JSON.stringify([]));
};

const readData = (file) => {
  try {
    const data = fs.readFileSync(file, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    return [];
  }
};

const writeData = (file, data) => {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
};

initFiles();

// Auth Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Token não fornecido' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido ou expirado' });
    req.user = user;
    next();
  });
};

// --- AUTH ROUTES ---

app.post('/api/auth/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Usuário e senha são obrigatórios' });

  const users = readData(USERS_FILE);
  if (users.find(u => u.username === username)) {
    return res.status(400).json({ error: 'Usuário já existe' });
  }

  const salt = bcrypt.genSaltSync(10);
  const passwordHash = bcrypt.hashSync(password, salt);

  const newUser = {
    id: uuidv4(),
    username,
    passwordHash,
    createdAt: new Date().toISOString()
  };

  users.push(newUser);
  writeData(USERS_FILE, users);

  res.status(201).json({ message: 'Usuário criado com sucesso' });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const users = readData(USERS_FILE);
  const user = users.find(u => u.username === username);

  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Credenciais inválidas' });
  }

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '8h' });
  res.json({ token, username: user.username });
});

// --- USER PROFILE ROUTES ---

app.get('/api/auth/profile', authenticateToken, (req, res) => {
  const users = readData(USERS_FILE);
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });
  
  res.json({
    id: user.id,
    username: user.username,
    displayName: user.displayName || user.username,
    email: user.email || '',
    phone: user.phone || ''
  });
});

app.put('/api/auth/profile', authenticateToken, (req, res) => {
  const { displayName, email, phone, currentPassword, password } = req.body;
  const users = readData(USERS_FILE);
  const index = users.findIndex(u => u.id === req.user.id);
  
  if (index === -1) return res.status(404).json({ error: 'Usuário não encontrado' });
  
  users[index].displayName = displayName || users[index].displayName || users[index].username;
  users[index].email = email !== undefined ? email : users[index].email;
  users[index].phone = phone !== undefined ? phone : users[index].phone;
  
  if (password && password.trim() !== '') {
    if (!currentPassword || currentPassword.trim() === '') {
      return res.status(400).json({ error: 'Senha atual é obrigatória para alterar a senha.' });
    }
    if (!bcrypt.compareSync(currentPassword, users[index].passwordHash)) {
      return res.status(401).json({ error: 'Senha atual incorreta.' });
    }
    const salt = bcrypt.genSaltSync(10);
    users[index].passwordHash = bcrypt.hashSync(password, salt);
  }
  
  writeData(USERS_FILE, users);
  
  res.json({
    message: 'Perfil atualizado.',
    user: {
      displayName: users[index].displayName,
      email: users[index].email,
      phone: users[index].phone
    }
  });
});

// --- TASK ROUTES ---

app.get('/api/tasks', authenticateToken, (req, res) => {
  const tasks = readData(TASKS_FILE);
  const userTasks = tasks.filter(t => t.userId === req.user.id);
  res.json(userTasks);
});

app.post('/api/tasks', authenticateToken, (req, res) => {
  const { title, description, status, deadline } = req.body;
  if (!title) return res.status(400).json({ error: 'Título é obrigatório' });

  const tasks = readData(TASKS_FILE);
  const newTask = {
    id: uuidv4(),
    userId: req.user.id,
    title,
    description: description || '',
    status: status || 'todo',
    deadline: deadline || null,
    completedAt: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };

  tasks.push(newTask);
  writeData(TASKS_FILE, tasks);

  res.status(201).json(newTask);
});

app.put('/api/tasks/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { title, description, status, deadline } = req.body;
  const tasks = readData(TASKS_FILE);
  const index = tasks.findIndex(t => t.id === id && t.userId === req.user.id);

  if (index === -1) return res.status(404).json({ error: 'Tarefa não encontrada' });

  const updatedTask = {
    ...tasks[index],
    title: title !== undefined ? title : tasks[index].title,
    description: description !== undefined ? description : tasks[index].description,
    status: status !== undefined ? status : tasks[index].status,
    deadline: deadline !== undefined ? deadline : tasks[index].deadline,
    updatedAt: new Date().toISOString()
  };

  tasks[index] = updatedTask;
  writeData(TASKS_FILE, tasks);

  res.json(updatedTask);
});

app.patch('/api/tasks/:id/done', authenticateToken, (req, res) => {
  const { id } = req.params;
  const tasks = readData(TASKS_FILE);
  const index = tasks.findIndex(t => t.id === id && t.userId === req.user.id);

  if (index === -1) return res.status(404).json({ error: 'Tarefa não encontrada' });

  const isCompleted = tasks[index].completedAt !== null;
  tasks[index].completedAt = isCompleted ? null : new Date().toISOString();
  tasks[index].status = isCompleted ? 'todo' : 'done';
  tasks[index].updatedAt = new Date().toISOString();

  writeData(TASKS_FILE, tasks);
  res.json(tasks[index]);
});

app.put('/api/tasks/:id/move', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  const tasks = readData(TASKS_FILE);
  const index = tasks.findIndex(t => t.id === id && t.userId === req.user.id);

  if (index === -1) return res.status(404).json({ error: 'Tarefa não encontrada' });

  tasks[index].status = status;
  tasks[index].updatedAt = new Date().toISOString();

  writeData(TASKS_FILE, tasks);
  res.json(tasks[index]);
});

app.delete('/api/tasks/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  let tasks = readData(TASKS_FILE);
  const index = tasks.findIndex(t => t.id === id && t.userId === req.user.id);

  if (index === -1) return res.status(404).json({ error: 'Tarefa não encontrada' });

  tasks = tasks.filter(t => !(t.id === id && t.userId === req.user.id));
  writeData(TASKS_FILE, tasks);

  res.json({ message: 'Tarefa excluída' });
});

app.listen(PORT, () => {
  console.log(`Servidor Kanban rodando na porta ${PORT}`);
});
