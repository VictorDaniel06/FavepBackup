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
    console.log('📦 Dados recebidos (sem senha):', { ...req.body, senha: '[PROTEGIDA]' });

    const { nome, email, telefone, senha, confirmarSenha } = req.body;

    if (!nome || !email || !telefone || !senha || !confirmarSenha) {
      console.warn('⚠️ Campos obrigatórios ausentes');
      return res.status(400).json({
        error: 'Campos obrigatórios: nome, email, telefone, senha, confirmarSenha.'
      });
    }

    if (senha !== confirmarSenha) {
      console.warn('⚠️ As senhas não coincidem durante o registro.');
      return res.status(400).json({ error: 'As senhas não coincidem.' });
    }

    try {
      const existingUser = await prisma.usuario.findUnique({ where: { email } });

      if (existingUser) {
        console.warn(`⚠️ Usuário com email ${email} já existe.`);
        return res.status(400).json({ error: 'Usuário já existe com este email.' });
      }

      console.log('🔐 Senha plain text para registro:', senha);
      const hashedPassword = await bcrypt.hash(senha, 10);
      console.log('🔒 Senha hashed (registro):', hashedPassword);

      const user = await prisma.usuario.create({
        data: {
          nome,
          email,
          telefone,
          senha: hashedPassword
        }
      });

      user.senha = undefined;

      console.log('✅ Usuário registrado com sucesso:', user.id);

      return res.status(201).json({
        user,
        token: generateToken({ id: user.id })
      });
    } catch (err) {
      console.error('❌ Erro no register:', err.message);
      return res.status(500).json({ error: 'Erro ao registrar usuário.' });
    }
  },

  // # login
  async login(req, res) {
    console.log('➡️ Requisição recebida em /login');
    console.log('📦 Email recebido para login:', req.body.email);

    const { email, senha } = req.body;

    if (!email || !senha) {
      console.warn('⚠️ Campos obrigatórios (email, senha) ausentes para login.');
      return res.status(400).json({ error: 'Email e senha são obrigatórios.' });
    }

    try {
      const user = await prisma.usuario.findUnique({ where: { email } });

      if (!user) {
        console.warn(`⚠️ Usuário com email ${email} não encontrado para login.`);
        return res.status(400).json({ error: 'Usuário não encontrado.' });
      }

      console.log('🔐 Senha plain text fornecida para login:', senha);
      console.log('🔑 Senha hashed do banco de dados (para comparação):', user.senha);

      const isMatch = await bcrypt.compare(senha, user.senha);
      
      console.log('Resultado da comparação de senhas (bcrypt.compare):', isMatch);

      if (!isMatch) {
        console.warn('⚠️ Senha inválida para o usuário:', email);
        return res.status(400).json({ error: 'Senha inválida.' });
      }

      user.senha = undefined;

      console.log('✅ Login realizado com sucesso para o usuário:', user.id);

      return res.status(200).json({
        user,
        token: generateToken({ id: user.id })
      });
    } catch (err) {
      console.error('❌ Erro no login:', err.message);
      return res.status(500).json({ error: 'Erro ao fazer login.' });
    }
  },

  // # update
  async update(req, res) {
    const authenticatedUserId = req.userId;

    console.log('➡️ Requisição recebida em /update');
    console.log('🆔 ID do usuário autenticado (via token):', authenticatedUserId);
    console.log('📦 Dados recebidos para atualização (sem senha):', { ...req.body, senha: '[PROTEGIDA]' });
    
    const { nome, email, telefone, senha, confirmarSenha } = req.body;
    try {
      const updateData = {};

      if (nome) updateData.nome = nome;
      if (email) updateData.email = email;
      if (telefone) updateData.telefone = telefone;

      if (senha || confirmarSenha) {
        console.log('🔄 Tentativa de atualização de senha detectada.');
        if (!senha || !confirmarSenha) {
          console.warn('⚠️ Senha e confirmarSenha são obrigatórios para alteração de senha.');
          return res.status(400).json({ error: 'Para alterar a senha, envie senha e confirmarSenha.' });
        }

        if (senha !== confirmarSenha) {
          console.warn('⚠️ As senhas não coincidem durante a atualização.');
          return res.status(400).json({ error: 'As senhas não coincidem.' });
        }

        console.log('🔐 Senha plain text para atualização:', senha);
        const hashedPassword = await bcrypt.hash(senha, 10);
        console.log('🔒 Senha hashed (atualização):', hashedPassword);

        updateData.senha = hashedPassword;
        console.log('🔐 Senha atualizada para o usuário:', authenticatedUserId);
      }

      const user = await prisma.usuario.update({
        where: { id: authenticatedUserId },
        data: updateData
      });

      user.senha = undefined;

      console.log('✅ Usuário atualizado com sucesso:', user.id);

      const newToken = generateToken({ id: user.id });

      return res.status(200).json({
        user,
        token: newToken
      });
    } catch (err) {
      console.error('❌ Erro ao atualizar usuário:', err.message);
      if (err.code === 'P2002' && err.meta?.target?.includes('email')) {
        return res.status(400).json({ error: 'Este email já está em uso.' });
      }
      if (err.code === 'P2025') {
        return res.status(404).json({ error: 'Usuário não encontrado para atualizar.' });
      }
      return res.status(500).json({ error: 'Erro ao atualizar usuário.' });
    }
  },

  // # delete
  async delete(req, res) {
    const authenticatedUserId = req.userId;

    console.log('➡️ Requisição recebida em /delete');
    console.log('🆔 ID do usuário a ser deletado (via token):', authenticatedUserId);
    
    try {
      await prisma.usuario.delete({ where: { id: authenticatedUserId } });
      console.log('🗑️ Usuário deletado com sucesso:', authenticatedUserId);
      return res.status(204).send();
    } catch (err) {
      console.error('❌ Erro ao deletar usuário:', err.message);
      if (err.code === 'P2025') {
        return res.status(404).json({ error: 'Usuário não encontrado para deletar.' });
      }
      return res.status(500).json({ error: 'Erro ao deletar usuário.' });
    }
  }
};
