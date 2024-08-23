require('dotenv').config();
const express = require('express');
const { PrismaClient } = require('@prisma/client');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const prisma = new PrismaClient();
const app = express();

app.use(express.json());

const secretKey = process.env.SECRET_KEY; // Hämta nyckeln från miljövariabler

// Route för rot-URL:en
app.get('/', (req, res) => {
	res.send('Welcome to Movie Reviews Backend!');
});

// Middleware för att verifiera JWT
const authenticateToken = (req, res, next) => {
	const authHeader = req.headers['authorization'];
	const token = authHeader && authHeader.split(' ')[1];
	if (!token) {
		console.error('Token saknas');
		return res.sendStatus(401);
	}

	jwt.verify(token, secretKey, (err, user) => {
		if (err) {
			console.error('Token verifiering misslyckades:', err.message);
			return res.sendStatus(403);
		}
		req.user = user;
		next();
	});
};

// Registrera en ny användare
app.post('/register', async (req, res, next) => {
	const { email, password } = req.body;
	const hashedPassword = await bcrypt.hash(password, 10);
	try {
		// Kontrollera om användaren redan existerar
		const existingUser = await prisma.user.findUnique({ where: { email } });
		if (existingUser) {
			return res.status(400).json({ error: 'Användaren existerar redan.' });
		}

		const user = await prisma.user.create({
			data: { email, password: hashedPassword },
		});
		res.json(user);
	} catch (error) {
		console.error(error); // Logga felet till konsolen
		next(error); // Skicka felet vidare till felhanteringsmiddleware
	}
});

// Logga in en användare
app.post('/login', async (req, res, next) => {
	const { email, password } = req.body;
	try {
		const user = await prisma.user.findUnique({ where: { email } });
		if (user && (await bcrypt.compare(password, user.password))) {
			const token = jwt.sign({ userId: user.id }, secretKey, {
				expiresIn: '1h',
			});
			res.json({ token });
		} else {
			res.status(401).json({ error: 'Ogiltig e-post eller lösenord.' });
		}
	} catch (error) {
		console.error(error); // Logga felet till konsolen
		next(error); // Skicka felet vidare till felhanteringsmiddleware
	}
});

// Hämta alla användare
app.get('/users', authenticateToken, async (req, res, next) => {
	try {
		const users = await prisma.user.findMany();
		res.json(users);
	} catch (error) {
		console.error(error); // Logga felet till konsolen
		next(error); // Skicka felet vidare till felhanteringsmiddleware
	}
});

// Skapa en ny användare (utan autentisering)
app.post('/users', async (req, res, next) => {
	const { email, password } = req.body;
	const hashedPassword = await bcrypt.hash(password, 10);
	try {
		const user = await prisma.user.create({
			data: { email, password: hashedPassword },
		});
		res.json(user);
	} catch (error) {
		console.error(error); // Logga felet till konsolen
		next(error); // Skicka felet vidare till felhanteringsmiddleware
	}
});

// Hämta alla recensioner
app.get('/reviews', authenticateToken, async (req, res, next) => {
	try {
		const reviews = await prisma.review.findMany();
		res.json(reviews);
	} catch (error) {
		console.error(error); // Logga felet till konsolen
		next(error); // Skicka felet vidare till felhanteringsmiddleware
	}
});

// Skapa en ny recension
app.post('/reviews', authenticateToken, async (req, res, next) => {
	const { title, content, userId } = req.body;
	try {
		const review = await prisma.review.create({
			data: { title, content, userId },
		});
		res.json(review);
	} catch (error) {
		console.error(error); // Logga felet till konsolen
		next(error); // Skicka felet vidare till felhanteringsmiddleware
	}
});

// Hämta en specifik recension
app.get('/reviews/:id', authenticateToken, async (req, res, next) => {
	const { id } = req.params;
	try {
		const review = await prisma.review.findUnique({
			where: { id: parseInt(id, 10) },
		});
		if (review) {
			res.json(review);
		} else {
			res.status(404).json({ error: 'Recensionen hittades inte.' });
		}
	} catch (error) {
		console.error(error); // Logga felet till konsolen
		next(error); // Skicka felet vidare till felhanteringsmiddleware
	}
});

// Uppdatera en recension
app.put('/reviews/:id', authenticateToken, async (req, res, next) => {
	const { id } = req.params;
	const { title, content } = req.body;
	try {
		const review = await prisma.review.update({
			where: { id: parseInt(id, 10) },
			data: { title, content },
		});
		res.json(review);
	} catch (error) {
		console.error(error); // Logga felet till konsolen
		next(error); // Skicka felet vidare till felhanteringsmiddleware
	}
});

// Ta bort en recension
app.delete('/reviews/:id', authenticateToken, async (req, res, next) => {
	const { id } = req.params;
	try {
		await prisma.review.delete({
			where: { id: parseInt(id, 10) },
		});
		res.json({ message: 'Recensionen har tagits bort.' });
	} catch (error) {
		console.error(error); // Logga felet till konsolen
		next(error); // Skicka felet vidare till felhanteringsmiddleware
	}
});

// Middleware för felhantering
app.use((err, req, res, next) => {
	console.error(err.stack);
	res
		.status(500)
		.json({ error: 'Ett internt serverfel inträffade.', details: err.message });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
	console.log(`Server is running on http://localhost:${port}`);
});
