import { PrismaClient, Role } from '../../generated/prisma'
import bcrypt from 'bcryptjs'
import { userFactory } from '../factories/user.factory'

export async function seedUsers(prisma: PrismaClient) {
  const password = await bcrypt.hash('Password@123', 10)

  // Admin user
  await prisma.user.upsert({
    where: { email: 'admin@example.com' },
    update: {},
    create: userFactory({
      name: 'Admin',
      email: 'admin@example.com',
      password,
      role: Role.ADMIN,
    }),
  })

  // Random users
  await prisma.user.createMany({
    data: Array.from({ length: 10 }).map(() =>
      userFactory({ password })
    ),
    skipDuplicates: true,
  })
}
