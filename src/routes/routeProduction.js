const express = require('express');
const router = express.Router();
const productionController = require('../controllers/productionController');

router.get('/productions', productionController.getAllProductions);
router.get('/productionGetById/:id', productionController.getProductionById);
router.post('/registerProduction', productionController.createProduction);
router.put('/updateProduction/:id', productionController.updateProduction);
router.delete('/productionDelete/:id', productionController.deleteProduction);

module.exports = router;
