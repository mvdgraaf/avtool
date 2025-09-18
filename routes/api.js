const express = require('express');
const router = express.Router();
const { PrismaClient } = require('../generated/prisma');

const prisma = new PrismaClient();

router.get('/product-groups', async (req, res, next) => {
    try {
        const groups = await prisma.productGroup.findMany({
            include: { items: true },
        });
        if (!groups) {
            return res.status(404).json({ error: 'Product groups not found' });
        }
        res.json(groups);
    } catch (err) {
        console.error('Error fetching product groups:', err);
        next(err);
    }
});

router.get('/product-items', async (req, res, next) => {
    try {
        const items = await prisma.productItem.findMany({
            include: { group: true },
        });
        if (!items) {
            return res.status(404).json({ error: 'Product items not found' });
        }
        res.json(items);
    } catch (err) {
        console.error('Error fetching product items:', err);
        next(err);
    }
})

router.get('/product-items/:id', async (req, res, next) => {
    try {
        const item = await prisma.productItem.findUnique({
            where: { id: parseInt(req.params.id) },
            include: { group: true },
        });
        if (!item) {
            return res.status(404).json({ error: 'Item not found' });
        }
        res.json(item);
    } catch (err) {
        console.error('Error fetching product item:', err);
        next(err);
    }
})

router.get('/customers', async (req, res, next) => {
    try {
        const customers = await prisma.customer.findMany();
        res.json(customers);
        if (!customers) {
            return res.status(404).json({ error: 'Customers not found' });
        }
    } catch (err) {
        console.error('Error fetching customers:', err);
        next(err);
    }
})

router.get('/customers/:id', async (req, res, next) => {
    try {
        const customer = await prisma.customer.findUnique({
            where: { id: parseInt(req.params.id) },
        });
        if (!customer) {
            return res.status(404).json({ error: 'Customer not found' });
        }
        res.json(customer);
    } catch (err) {
        console.error('Error fetching customer:', err);
        next(err);
    }
})

router.get('/rentals', async (req, res, next) => {
    try {
        const rentals = await prisma.rental.findMany({
            include: { items: true, customer: true },
        });
        if (!rentals) {
            return res.status(404).json({ error: 'Rentals not found' });
        }
        res.json(rentals);
    } catch (err) {
        console.error('Error fetching rentals:', err);
        next(err);
    }
})

router.get('/rentals/:id', async (req, res, next) => {
    try {
        const rental = await prisma.rental.findUnique({
            where: { id: parseInt(req.params.id) },
            include: { items: true, customer: true },
        });
        if (!rental) {
            return res.status(404).json({ error: 'Rental not found' });
        }
        res.json(rental);
    } catch (err) {
        console.error('Error fetching rental:', err);
        next(err);
    }
})

router.get('/rentals/:id/items', async (req, res, next) => {
    try {
        const rental = await prisma.rental.findUnique({
            where: { id: parseInt(req.params.id) },
            include: { items: true },
        });
        if (!rental) {
            return res.status(404).json({ error: 'Rental not found' });
        }
        res.json(rental.items);
    } catch (err) {
        console.error('Error fetching rental items:', err);
        next(err);
    }
})

router.get('/rentals/:id/items/:itemId', async (req, res, next) => {
    try {
        const rental = await prisma.rental.findUnique({
            where: { id: parseInt(req.params.id) },
            include: {
                items: {
                    include: { item: true },
                },
            },
        });
        if (!rental) {
            return res.status(404).json({ error: 'Rental not found' });
        }
        const rentalItem = rental.items.find(
            (ri) => ri.item.id === parseInt(req.params.itemId)
        );
        if (!rentalItem) {
            return res.status(404).json({ error: 'Item not found in this rental' });
        }
        res.json(rentalItem.item);
    } catch (err) {
        console.error('Error fetching rental item:', err);
        next(err);
    }
});

router.post('/alert', async (req, res, next) => {

})


module.exports = router;
