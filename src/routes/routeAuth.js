const express = require('express');
const router = express.Router();
const authMiddleware = require('../middlewares/auth');
const authController = require('../controllers/authController');

router.post('/register', authController.register);
router.post('/login', authController.login);
router.put('/update', authMiddleware, authController.update);
router.delete('/delete', authMiddleware, authController.delete);

module.exports = router;