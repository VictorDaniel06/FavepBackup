const prisma = require('../lib/prisma');
const { PrismaClient } = require('@prisma/client');

module.exports = {
  // # getAllProperties
  async getAllProperties(req, res) {
    console.log('➡️ Requisição recebida para listar todas as propriedades');
    try {
      const properties = await prisma.propriedade.findMany({
        include: {
          usuario: true,
          producoes: {
            select: {
              cultura: true,
              data: true
            },
            orderBy: {
              data: 'desc'
            }
          }
        },
      });

      const propertiesWithAllCultures = properties.map(property => {
        const culturas = property.producoes.map(prod => prod.cultura); 
        const { producoes, ...rest } = property; 
        return { ...rest, culturas }; 
      });


      console.log('✅ Propriedades listadas com sucesso:', propertiesWithAllCultures.length);
      res.status(200).json(propertiesWithAllCultures);
    } catch (error) {
      console.error('❌ Erro ao listar propriedades:', error);
      res.status(500).json({ error: 'Ops! Ocorreu um erro ao buscar as propriedades.' });
    }
  },

  // # getPropertyById
  async getPropertyById(req, res) {
    const { nomepropriedade } = req.params;
    console.log(`➡️ Requisição recebida para buscar propriedade: "${nomepropriedade}"`);
    try {
      const property = await prisma.propriedade.findUnique({
        where: {
          nomepropriedade: nomepropriedade,
        },
        include: {
          usuario: true,
          producoes: {
            select: {
              cultura: true,
              data: true
            },
            orderBy: {
              data: 'desc'
            }
          }
        },
      });

      if (!property) {
        console.warn(`⚠️ Propriedade "${nomepropriedade}" não encontrada.`);
        return res.status(404).json({ error: `Propriedade "${nomepropriedade}" não encontrada.` });
      }

      const culturas = property.producoes.map(prod => prod.cultura); 
      const { producoes, ...rest } = property; 


      console.log('✅ Propriedade encontrada com sucesso:', property.nomepropriedade);
      res.status(200).json({ ...rest, culturas }); 
    } catch (error) {
      console.error('❌ Erro ao buscar propriedade:', error);
      res.status(500).json({ error: 'Ops! Ocorreu um erro ao buscar esta propriedade.' });
    }
  },

  // # createProperty
  async createProperty(req, res) {
    const { nomepropriedade, area_ha, areaproducao, localizacao, usuarioId } = req.body;
    console.log('➡️ Requisição recebida para criar uma nova propriedade');
    console.log('📦 Dados recebidos:', req.body);

    if (!nomepropriedade || !area_ha || !areaproducao || !localizacao || !usuarioId) {
      console.warn('⚠️ Campos obrigatórios para criar propriedade ausentes.');
      return res.status(400).json({ error: 'Por favor, preencha todos os campos obrigatórios: nome da propriedade, área em hectares, área de produção, localização e ID do usuário.' });
    }

    try {
      const existingProperty = await prisma.propriedade.findUnique({ where: { nomepropriedade } });
      if (existingProperty) {
        console.warn(`⚠️ Já existe uma propriedade com o nome "${nomepropriedade}".`);
        return res.status(400).json({ error: `Já existe uma propriedade com o nome "${nomepropriedade}". Escolha outro nome.` });
      }

      const newProperty = await prisma.propriedade.create({
        data: {
          nomepropriedade,
          area_ha,
          areaproducao,
          localizacao,
          usuario: {
            connect: { id: usuarioId },
          },
        },
        include: {
          usuario: true,
          producoes: {
            select: { cultura: true, data: true },
            orderBy: { data: 'desc' }
          }
        },
      });

      const culturas = newProperty.producoes.map(prod => prod.cultura); 
      const { producoes, ...rest } = newProperty;


      console.log('✅ Propriedade criada com sucesso:', newProperty.nomepropriedade);
      res.status(201).json({
        message: 'Propriedade cadastrada com sucesso!',
        property: { ...rest, culturas } 
      });
    } catch (error) {
      console.error('❌ Erro ao criar propriedade:', error);
      if (error.code === 'P2025' && error.meta?.cause?.includes('No \'usuario\' record(s)')) {
          console.warn(`⚠️ Usuário com ID "${usuarioId}" não encontrado para associação.`);
          return res.status(400).json({ error: `O usuário com o ID "${usuarioId}" fornecido não existe.` });
      }
      res.status(500).json({ error: 'Ops! Não foi possível cadastrar a propriedade. Tente novamente mais tarde.' });
    }
  },

  // # updateProperty
  async updateProperty(req, res) {
    const { nomepropriedade } = req.params;
    const { area_ha, areaproducao, localizacao, usuarioId } = req.body;
    console.log(`➡️ Requisição recebida para atualizar propriedade: "${nomepropriedade}"`);
    console.log('📦 Dados de atualização:', req.body);

    try {
      const updatedProperty = await prisma.propriedade.update({
        where: {
          nomepropriedade: nomepropriedade,
        },
        data: {
          area_ha,
          areaproducao,
          localizacao,
          ...(usuarioId && { usuario: { connect: { id: usuarioId } } }),
        },
        include: {
          usuario: true,
          producoes: {
            select: { cultura: true, data: true },
            orderBy: { data: 'desc' }
          }
        },
      });

      const culturas = updatedProperty.producoes.map(prod => prod.cultura); 
      const { producoes, ...rest } = updatedProperty;


      console.log('🔄 Propriedade atualizada com sucesso:', updatedProperty.nomepropriedade);
      res.status(200).json({
        message: 'Propriedade atualizada com sucesso!',
        property: { ...rest, culturas } 
      });
    } catch (error) {
      console.error('❌ Erro ao atualizar propriedade:', error);
      if (error.code === 'P2025') {
        if (error.meta?.modelName === 'propriedade') {
          console.warn(`⚠️ Propriedade "${nomepropriedade}" não encontrada para atualização.`);
          return res.status(404).json({ error: `Não foi possível encontrar a propriedade "${nomepropriedade}" para atualizar.` });
        } else if (error.meta?.cause?.includes('No \'usuario\' record(s)')) {
          console.warn(`⚠️ Usuário com ID "${usuarioId}" não encontrado para associação.`);
          return res.status(400).json({ error: `O usuário com o ID "${usuarioId}" fornecido não existe.` });
        }
      }
      res.status(500).json({ error: 'Ops! Ocorreu um erro ao atualizar a propriedade. Tente novamente.' });
    }
  },

  // # deleteProperty
  async deleteProperty(req, res) {
    const { nomepropriedade } = req.params;
    console.log(`➡️ Requisição recebida para deletar propriedade: "${nomepropriedade}"`);
    try {
      await prisma.producao.deleteMany({
        where: {
          nomepropriedade: nomepropriedade, 
        },
      });
      console.log(`🗑️ Produções associadas à propriedade "${nomepropriedade}" deletadas.`);

      await prisma.propriedade.delete({
        where: {
          nomepropriedade: nomepropriedade,
        },
      });
      console.log('🗑️ Propriedade deletada com sucesso:', nomepropriedade);
      res.status(204).send();
    } catch (error) {
      console.error('❌ Erro ao deletar propriedade:', error);
      if (error.code === 'P2025') {
        console.warn(`⚠️ Propriedade "${nomepropriedade}" não encontrada para deleção.`);
        return res.status(404).json({ error: `Não foi possível encontrar a propriedade "${nomepropriedade}" para deletar.` });
      }
      res.status(500).json({ error: 'Ops! Ocorreu um erro ao deletar a propriedade. Verifique se não há registros associados.' });
    }
  },
};