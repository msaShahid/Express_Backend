import { Prisma, Role } from '../../generated/prisma'
import { faker } from '@faker-js/faker'

export const userFactory = (
  overrides?: Partial<Prisma.UserCreateInput>
): Prisma.UserCreateInput => ({
  name: faker.person.fullName(),
  email: faker.internet.email().toLowerCase(),
  password: faker.internet.password(),
  role: Role.USER,
  emailVerified: true,
  isActive: true,
  ...overrides,
})
