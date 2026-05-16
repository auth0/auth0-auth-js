import { Router } from 'express';

interface Employee {
  id: string;
  name: string;
  email: string;
  department: string;
  role: string;
  startDate: string;
}

interface Department {
  id: string;
  name: string;
  headcount: number;
  manager: string;
  budget: number;
  location: string;
}

export function createRoutes(employees: Employee[], departments: Department[]): Router {
  const router = Router();

  router.get('/employees', (req, res) => {
    const { department } = req.query;
    let result = employees;
    if (department && typeof department === 'string') {
      result = employees.filter((e) => e.department.toLowerCase() === department.toLowerCase());
    }
    res.json({ employees: result, total: result.length });
  });

  router.get('/employees/:id', (req, res) => {
    const employee = employees.find((e) => e.id === req.params.id);
    if (!employee) {
      res.status(404).json({ error: 'Employee not found' });
      return;
    }
    res.json(employee);
  });

  router.get('/departments', (_req, res) => {
    res.json({ departments });
  });

  router.get('/departments/:id', (req, res) => {
    const dept = departments.find((d) => d.id === req.params.id);
    if (!dept) {
      res.status(404).json({ error: 'Department not found' });
      return;
    }
    res.json(dept);
  });

  return router;
}
