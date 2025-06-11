const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const prisma = require('../lib/prisma');
const authConfig = require('../config/auth.json');

function generateToken(params = {}) {
  return jwt.sign(params, authConfig.secret, { expiresIn: 86400 });
}

module.exports = {
  // # register
  async register(req, res) {
    console.log('➡️ Requisição recebida em /register');
    console.log('📦 Dados recebidos:', req.body);

    const { nome, email, telefone, senha, confirmarSenha } = req.body;

    if (!nome || !email || !telefone || !senha || !confirmarSenha) {
      console.warn('⚠️ Campos obrigatórios ausentes');
      return res.status(400).json({
        error: 'Campos obrigatórios: nome, email, telefone, senha, confirmarSenha.'
      });
    }

    if (senha !== confirmarSenha) {
      return res.status(400).json({ error: 'As senhas não coincidem.' });
    }

    try {
      const existingUser = await prisma.usuario.findUnique({ where: { email } });

      if (existingUser) {
        return res.status(400).json({ error: 'Usuário já existe com este email.' });
      }

      const hashedPassword = await bcrypt.hash(senha, 10);

      const user = await prisma.usuario.create({
        data: {
          nome,
          email,
          telefone,
          senha: hashedPassword
        }
      });

      user.senha = undefined;

      console.log('✅ Usuário registrado com sucesso:', user);

      return res.status(201).json({
        user,
        token: generateToken({ id: user.id })
      });
    } catch (err) {
      console.error('❌ Erro no register:', err);
      return res.status(500).json({ error: 'Erro ao registrar usuário.' });
    }
  },

  // # login
  async login(req, res) {
    console.log('➡️ Requisição recebida em /login');
    const { email, senha } = req.body;

    if (!email || !senha) {
      console.warn('⚠️ Campos obrigatórios ausentes');
      return res.status(400).json({ error: 'Email e senha são obrigatórios.' });
    }

    try {
      const user = await prisma.usuario.findUnique({ where: { email } });

      if (!user) {
        return res.status(400).json({ error: 'Usuário não encontrado.' });
      }

      const isMatch = await bcrypt.compare(senha, user.senha);
      if (!isMatch) {
        return res.status(400).json({ error: 'Senha inválida.' });
      }

      user.senha = undefined;

      console.log('✅ Login realizado com sucesso');

      return res.status(200).json({
        user,
        token: generateToken({ id: user.id })
      });
    } catch (err) {
      console.error('❌ Erro no login:', err);
      return res.status(500).json({ error: 'Erro ao fazer login.' });
    }
  },

  // # update
  async update(req, res) {
    const { nome, email, telefone, senha, confirmarSenha } = req.body;
    const userId = req.userId;

    try {
      const updateData = {};

      if (nome) updateData.nome = nome;
      if (email) updateData.email = email;
      if (telefone) updateData.telefone = telefone;

      if (senha || confirmarSenha) {
        if (!senha || !confirmarSenha) {
          return res.status(400).json({ error: 'Para alterar a senha, envie senha e confirmarSenha.' });
        }

        if (senha !== confirmarSenha) {
          return res.status(400).json({ error: 'As senhas não coincidem.' });
        }

        const hashedPassword = await bcrypt.hash(senha, 10);
        updateData.senha = hashedPassword;
        console.log('🔐 Senha atualizada para o usuário:', userId);
      }

      const user = await prisma.usuario.update({
        where: { id: userId },
        data: updateData
      });

      user.senha = undefined;

      console.log('🔄 Usuário atualizado:', user);

      const newToken = generateToken({ id: user.id });

      return res.status(200).json({
        user,
        token: newToken
      });
    } catch (err) {
      console.error('❌ Erro ao atualizar usuário:', err);
      return res.status(500).json({ error: 'Erro ao atualizar usuário.' });
    }
  },

  // # delete
  async delete(req, res) {
    const userId = req.userId;

    try {
      await prisma.usuario.delete({ where: { id: userId } });
      console.log('🗑️ Usuário deletado:', userId);
      return res.status(204).send();
    } catch (err) {
      console.error('❌ Erro ao deletar usuário:', err);
      return res.status(500).json({ error: 'Erro ao deletar usuário.' });
      }
    }
  };