import { Router } from 'express';

interface Policy {
  id: string;
  name: string;
  maxAmount: number;
  requiresApproval: boolean;
  approver: string | null;
  category: string;
}

export function createRoutes(policies: Policy[]): Router {
  const router = Router();

  router.get('/policies', (_req, res) => {
    res.json({ policies });
  });

  router.get('/policies/:id', (req, res) => {
    const policy = policies.find((p) => p.id === req.params.id);
    if (!policy) {
      res.status(404).json({ error: 'Policy not found' });
      return;
    }
    res.json(policy);
  });

  return router;
}
