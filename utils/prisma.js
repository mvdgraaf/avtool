'use strict';

let PrismaClient;

try {
  ({ PrismaClient } = require('../generated/prisma'));
} catch (e) {
  try {
    ({ PrismaClient } = require('@prisma/client'));
  } catch {
    throw new Error('PrismaClient kon niet worden geladen. Installeer @prisma/client en voer "npx prisma generate" uit.');
  }
}

const prisma = new PrismaClient();

// Early, duidelijke fout i.p.v. "Cannot read properties of undefined (reading 'findUnique')"
if (!prisma.user) {
  throw new Error('Prisma client lijkt geen "user" model te bevatten. Controleer je schema en run "npx prisma generate".');
}

module.exports = prisma;
