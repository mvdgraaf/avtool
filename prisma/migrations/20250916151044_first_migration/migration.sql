-- CreateEnum
CREATE TYPE "public"."ItemStatus" AS ENUM ('AVAILABLE', 'RENTED', 'MAINTENANCE', 'LOST');

-- CreateEnum
CREATE TYPE "public"."RentalStatus" AS ENUM ('PENDING', 'ACTIVE', 'COMPLETED', 'CANCELLED');

-- CreateTable
CREATE TABLE "public"."ProductGroup" (
    "id" SERIAL NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "brand" TEXT,
    "category" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ProductGroup_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."ProductItem" (
    "id" SERIAL NOT NULL,
    "serialNumber" TEXT,
    "condition" TEXT,
    "status" "public"."ItemStatus" NOT NULL DEFAULT 'AVAILABLE',
    "groupId" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ProductItem_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."Customer" (
    "id" SERIAL NOT NULL,
    "name" TEXT NOT NULL,
    "email" TEXT,
    "phone" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Customer_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."Rental" (
    "id" SERIAL NOT NULL,
    "customerId" INTEGER NOT NULL,
    "startDate" TIMESTAMP(3) NOT NULL,
    "endDate" TIMESTAMP(3) NOT NULL,
    "status" "public"."RentalStatus" NOT NULL DEFAULT 'PENDING',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Rental_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."RentalItem" (
    "id" SERIAL NOT NULL,
    "rentalId" INTEGER NOT NULL,
    "itemId" INTEGER NOT NULL,

    CONSTRAINT "RentalItem_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "ProductItem_serialNumber_key" ON "public"."ProductItem"("serialNumber");

-- AddForeignKey
ALTER TABLE "public"."ProductItem" ADD CONSTRAINT "ProductItem_groupId_fkey" FOREIGN KEY ("groupId") REFERENCES "public"."ProductGroup"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."Rental" ADD CONSTRAINT "Rental_customerId_fkey" FOREIGN KEY ("customerId") REFERENCES "public"."Customer"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."RentalItem" ADD CONSTRAINT "RentalItem_rentalId_fkey" FOREIGN KEY ("rentalId") REFERENCES "public"."Rental"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."RentalItem" ADD CONSTRAINT "RentalItem_itemId_fkey" FOREIGN KEY ("itemId") REFERENCES "public"."ProductItem"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
