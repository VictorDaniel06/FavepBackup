const express = require('express');
const router = express.Router();
const productionController = require('../controllers/financesController');

router.get('/finances', productionController.getAllFinanceiros);
router.get('/financeGetById/:id', productionController.getFinanceiroById);
router.post('/registerFinance', productionController.createFinanceiro);
router.put('/financeUpdate/:id', productionController.updateFinanceiro);

module.exports = router;
