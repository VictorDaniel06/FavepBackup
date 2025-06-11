-- CreateTable
CREATE TABLE "usuario" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "nome" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "telefone" TEXT,
    "senha" TEXT NOT NULL
);

-- CreateTable
CREATE TABLE "propriedade" (
    "nomepropriedade" TEXT NOT NULL PRIMARY KEY,
    "areaproducao" REAL NOT NULL,
    "localizacao" TEXT NOT NULL,
    "usuarioId" TEXT NOT NULL,
    "area_ha" INTEGER NOT NULL,
    CONSTRAINT "propriedade_usuarioId_fkey" FOREIGN KEY ("usuarioId") REFERENCES "usuario" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "producao" (
    "safra" TEXT NOT NULL,
    "areaproducao" REAL NOT NULL,
    "data" DATETIME NOT NULL,
    "nomepropriedade" TEXT NOT NULL,
    "area_ha" INTEGER NOT NULL,
    "cultura" TEXT NOT NULL,
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    CONSTRAINT "producao_nomepropriedade_fkey" FOREIGN KEY ("nomepropriedade") REFERENCES "propriedade" ("nomepropriedade") ON DELETE RESTRICT ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "financeiro" (
    "nomepropriedade" TEXT NOT NULL,
    "descricao" TEXT NOT NULL,
    "valor" REAL NOT NULL,
    "data" DATETIME NOT NULL,
    "tipo" TEXT NOT NULL,
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    CONSTRAINT "financeiro_nomepropriedade_fkey" FOREIGN KEY ("nomepropriedade") REFERENCES "propriedade" ("nomepropriedade") ON DELETE RESTRICT ON UPDATE CASCADE
);

-- CreateIndex
CREATE UNIQUE INDEX "usuario_email_key" ON "usuario"("email");

-- CreateIndex
CREATE UNIQUE INDEX "propriedade_nomepropriedade_key" ON "propriedade"("nomepropriedade");
