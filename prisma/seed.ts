import { prisma } from '../src/prisma/client' 
import { seedUsers } from './seeds/user.seed'

if (process.env.NODE_ENV === 'production') {
  throw new Error('Seeding not allowed in production')
}

async function main() {
  console.log('Seeding started...')
  await seedUsers(prisma)
  console.log('Seeding finished')
}

main()
  .catch((error) => {
    console.error('Seeding failed:', error)
    process.exit(1)
  })
  .finally(async () => {
    await prisma.$disconnect()
  })
