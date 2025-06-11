const express = require('express');
const router = express.Router();
const propertyController = require('../controllers/propertyController'); 


router.get('/properties', propertyController.getAllProperties);
router.get('/propGetById/:nomepropriedade', propertyController.getPropertyById);
router.post('/registerProp', propertyController.createProperty);
router.put('/updateProp/:nomepropriedade', propertyController.updateProperty);
router.delete('/propDelete/:nomepropriedade', propertyController.deleteProperty);

module.exports = router;