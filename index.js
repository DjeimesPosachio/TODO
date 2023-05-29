const { PrismaClient } = require('@prisma/client');
const express = require('express');
const bcrypt = require('bcryptjs');
const app = express();
app.use(express.json());

const prisma = new PrismaClient();

// Middleware de autenticação
const authenticateUser = async (req, res, next) => {
  const { userId } = req.session;
  
  if (!userId) {
    return res.status(401).json({ error: 'Usuário não autenticado.' });
  }

  try {
    const user = await prisma.user.findUnique({
      where: {
        id: userId
      }
    });

    if (!user) {
      return res.status(401).json({ error: 'Usuário não autenticado.' });
    }

    req.user = user; // Armazena o usuário no objeto de solicitação (request) para uso posterior
    next(); // Chama o próximo middleware ou rota
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao autenticar usuário.' });
  }
};

app.post('/users', async (req, res) => {
  const { nome, email, senha } = req.body;

  // Validação dos campos
  if (!nome || !email || !senha) {
    return res.status(400).json({ error: 'Todos os campos devem ser preenchidos.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(senha, 10);

    const newUser = await prisma.user.create({
      data: {
        nome,
        email,
        senha: hashedPassword
      }
    });
    res.status(201).json(newUser);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao registrar usuário.' });
  }
});

app.post('/login', async (req, res) => {
  const { email, senha } = req.body;

  // Validação dos campos
  if (!email || !senha) {
    return res.status(400).json({ error: 'Todos os campos devem ser preenchidos.' });
  }

  try {
    const user = await prisma.user.findUnique({
      where: {
        email
      }
    });

    if (!user) {
      res.status(404).json({ error: 'Usuário não encontrado.' });
      return;
    }

    const passwordMatch = await bcrypt.compare(senha, user.senha);

    if (!passwordMatch) {
      res.status(401).json({ error: 'Senha incorreta.' });
      return;
    }

    // Define o ID do usuário na sessão para fins de autenticação
    req.session.userId = user.id;

    res.json({ message: 'Login bem-sucedido!' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao fazer login.' });
  }
});

app.post('/tasks', authenticateUser, async (req, res) => {
  const { titulo, descricao } = req.body;

  // Validação dos campos
  if (!titulo || !descricao) {
    return res.status(400).json({ error: 'Todos os campos devem ser preenchidos.' });
  }

  try {
    const newTask = await prisma.task.create({
      data: {
        titulo,
        descricao,
        userId: req.user.id // Obtém o ID do usuário da sessão
      }
    });
    res.status(201).json(newTask);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao criar tarefa.' });
  }
});

// Outras rotas de tarefas...

const port = 3000;
app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});
