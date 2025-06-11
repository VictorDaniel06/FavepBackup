const prisma = require('../lib/prisma');

module.exports = {
  async getAllFinanceiros(req, res) {
    console.log('➡️ Requisição recebida para listar todos os registros financeiros');
    try {
      const financeiros = await prisma.financeiro.findMany({
        include: {
          propriedade: true,
        },
      });
      console.log(`✅ ${financeiros.length} registros financeiros listados com sucesso.`);
      res.status(200).json(financeiros);
    } catch (error) {
      console.error('❌ Erro ao listar registros financeiros:', error);
      res.status(500).json({ error: 'Ops! Ocorreu um erro ao buscar os registros financeiros.' });
    }
  },

  async getFinanceiroById(req, res) {
    const { id } = req.params;
    const financeiroId = parseInt(id, 10);

    if (isNaN(financeiroId)) {
      console.warn(`⚠️ ID inválido fornecido: "${id}". Esperado um número.`);
      return res.status(400).json({ error: 'ID inválido. Por favor, forneça um número válido.' });
    }

    console.log(`➡️ Requisição recebida para buscar registro financeiro com ID: ${financeiroId}`);
    try {
      const financeiro = await prisma.financeiro.findUnique({
        where: {
          id: financeiroId,
        },
        include: {
          propriedade: true,
        },
      });

      if (!financeiro) {
        console.warn(`⚠️ Registro financeiro com ID ${financeiroId} não encontrado.`);
        return res.status(404).json({ error: `Registro financeiro com ID ${financeiroId} não encontrado.` });
      }
      console.log(`✅ Registro financeiro com ID ${financeiro.id} encontrado com sucesso.`);
      res.status(200).json(financeiro);
    } catch (error) {
      console.error('❌ Erro ao buscar registro financeiro:', error);
      res.status(500).json({ error: 'Ops! Ocorreu um erro ao buscar este registro financeiro.' });
    }
  },

  async createFinanceiro(req, res) {
    const { nomepropriedade, descricao, valor, data, tipo } = req.body;
    console.log('➡️ Requisição recebida para criar um novo registro financeiro');
    console.log('📦 Dados recebidos:', req.body);

    if (!nomepropriedade || !descricao || valor === undefined || !data || !tipo) {
      console.warn('⚠️ Campos obrigatórios para criar registro financeiro ausentes ou inválidos.');
      return res.status(400).json({ error: 'Por favor, preencha todos os campos obrigatórios: nome da propriedade, descrição, valor, data e tipo.' });
    }
    
    if (typeof valor !== 'number' || isNaN(valor)) {
      console.warn(`⚠️ Valor inválido fornecido: "${valor}". Esperado um número.`);
      return res.status(400).json({ error: 'O campo "valor" deve ser um número válido.' });
    }

    try {
      const newFinanceiro = await prisma.financeiro.create({
        data: {
          descricao,
          valor,
          data: new Date(data),
          tipo,
          propriedade: {
            connect: { nomepropriedade: nomepropriedade },
          },
        },
        include: {
          propriedade: true,
        },
      });
      console.log(`✅ Registro financeiro com ID ${newFinanceiro.id} criado com sucesso.`);
      res.status(201).json({
        message: 'Registro financeiro cadastrado com sucesso!',
        financeiro: newFinanceiro,
      });
    } catch (error) {
      console.error('❌ Erro ao criar registro financeiro:', error);
      if (error.code === 'P2025') {
        console.warn(`⚠️ Propriedade "${nomepropriedade}" não encontrada para associação ao registro financeiro.`);
        return res.status(400).json({ error: `A propriedade "${nomepropriedade}" não existe. Verifique o nome da propriedade.` });
      }
      res.status(500).json({ error: 'Ops! Não foi possível cadastrar o registro financeiro. Tente novamente mais tarde.' });
    }
  },

  async updateFinanceiro(req, res) {
    const { id } = req.params;
    const { nomepropriedade, descricao, valor, data, tipo } = req.body;
    const financeiroId = parseInt(id, 10);

    if (isNaN(financeiroId)) {
      console.warn(`⚠️ ID inválido fornecido: "${id}". Esperado um número.`);
      return res.status(400).json({ error: 'ID inválido. Por favor, forneça um número válido.' });
    }

    console.log(`➡️ Requisição recebida para atualizar registro financeiro com ID: ${financeiroId}`);
    console.log('📦 Dados de atualização:', req.body);

    const dataToUpdate = {};
    if (descricao) dataToUpdate.descricao = descricao;
    if (valor !== undefined && typeof valor === 'number' && !isNaN(valor)) dataToUpdate.valor = valor;
    if (data) dataToUpdate.data = new Date(data);
    if (tipo) dataToUpdate.tipo = tipo;
    if (nomepropriedade) {
      dataToUpdate.propriedade = {
        connect: { nomepropriedade: nomepropriedade },
      };
    }

    if (Object.keys(dataToUpdate).length === 0) {
      console.warn('⚠️ Nenhum dado válido fornecido para atualização.');
      return res.status(400).json({ error: 'Nenhum dado válido fornecido para atualização.' });
    }

    try {
      const updatedFinanceiro = await prisma.financeiro.update({
        where: {
          id: financeiroId,
        },
        data: dataToUpdate,
        include: {
          propriedade: true,
        },
      });
      console.log(`🔄 Registro financeiro com ID ${updatedFinanceiro.id} atualizado com sucesso.`);
      res.status(200).json({
        message: 'Registro financeiro atualizado com sucesso!',
        financeiro: updatedFinanceiro,
      });
    } catch (error) {
      console.error('❌ Erro ao atualizar registro financeiro:', error);
      if (error.code === 'P2025') {
        console.warn(`⚠️ Registro financeiro com ID ${financeiroId} não encontrado para atualização.`);
        return res.status(404).json({ error: `Não foi possível encontrar o registro financeiro com ID ${financeiroId} para atualizar.` });
      }
      if (error.code === 'P2014') {
        console.warn(`⚠️ A propriedade "${nomepropriedade}" não existe para associação.`);
        return res.status(400).json({ error: `A propriedade "${nomepropriedade}" não existe. Verifique o nome da propriedade.` });
      }
      res.status(500).json({ error: 'Ops! Ocorreu um erro ao atualizar o registro financeiro. Tente novamente.' });
    }
  },

  async deleteFinanceiro(req, res) {
    const { id } = req.params;
    const financeiroId = parseInt(id, 10);

    if (isNaN(financeiroId)) {
      console.warn(`⚠️ ID inválido fornecido: "${id}". Esperado um número.`);
      return res.status(400).json({ error: 'ID inválido. Por favor, forneça um número válido.' });
    }

    console.log(`➡️ Requisição recebida para deletar registro financeiro com ID: ${financeiroId}`);
    try {
      await prisma.financeiro.delete({
        where: {
          id: financeiroId,
        },
      });
      console.log(`🗑️ Registro financeiro com ID ${financeiroId} deletado com sucesso.`);
      res.status(204).send();
    } catch (error) {
      console.error('❌ Erro ao deletar registro financeiro:', error);
      if (error.code === 'P2025') {
        console.warn(`⚠️ Registro financeiro com ID ${financeiroId} não encontrado para deleção.`);
        return res.status(404).json({ error: `Não foi possível encontrar o registro financeiro com ID ${financeiroId} para deletar.` });
      }
      res.status(500).json({ error: 'Ops! Ocorreu um erro ao deletar o registro financeiro. Verifique se não há registros associados ou se o ID está correto.' });
    }
  },
};