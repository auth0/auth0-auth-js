import { Router } from 'express';

interface Expense {
  id: string;
  amount: number;
  currency: string;
  status: string;
  submitter: string;
  description: string;
}

export function createRoutes(expenses: Expense[]): Router {
  const router = Router();

  router.get('/expenses', (req, res) => {
    const { status } = req.query;
    let result = expenses;
    if (status && typeof status === 'string') {
      result = expenses.filter((e) => e.status === status);
    }
    res.json({ expenses: result, total: result.length });
  });

  router.get('/expenses/:id', (req, res) => {
    const expense = expenses.find((e) => e.id === req.params.id);
    if (!expense) {
      res.status(404).json({ error: 'Expense not found' });
      return;
    }
    res.json(expense);
  });

  router.post('/expenses/:id/approve', (req, res) => {
    const expense = expenses.find((e) => e.id === req.params.id);
    if (!expense) {
      res.status(404).json({ error: 'Expense not found' });
      return;
    }
    expense.status = 'approved';
    res.json({ ...expense, approvedBy: res.locals.claims.sub, approvedAt: new Date().toISOString() });
  });

  router.post('/expenses', (req, res) => {
    const { amount, currency, description } = req.body;
    const newExpense = {
      id: `exp_${expenses.length + 1}`,
      amount,
      currency: currency ?? 'USD',
      status: 'pending',
      submitter: res.locals.claims.sub,
      description,
    };
    expenses.push(newExpense);
    res.status(201).json(newExpense);
  });

  return router;
}
