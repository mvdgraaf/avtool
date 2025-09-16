/*
  Warnings:

  - Added the required column `password` to the `Customer` table without a default value. This is not possible if the table is not empty.

*/
-- CreateEnum
CREATE TYPE "public"."UserRole" AS ENUM ('ADMIN', 'USER');

-- DropForeignKey
ALTER TABLE "public"."ProductItem" DROP CONSTRAINT "ProductItem_groupId_fkey";

-- AlterTable
ALTER TABLE "public"."Customer" ADD COLUMN     "password" TEXT NOT NULL;

-- CreateTable
CREATE TABLE "public"."User" (
    "id" SERIAL NOT NULL,
    "email" TEXT NOT NULL,
    "name" TEXT,
    "password" TEXT NOT NULL,
    "role" "public"."UserRole" NOT NULL DEFAULT 'USER',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "public"."User"("email");

-- AddForeignKey
ALTER TABLE "public"."ProductItem" ADD CONSTRAINT "ProductItem_groupId_fkey" FOREIGN KEY ("groupId") REFERENCES "public"."ProductGroup"("id") ON DELETE CASCADE ON UPDATE CASCADE;
