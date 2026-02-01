import { Prisma, Role, UserStatus } from '../../generated/prisma'
import { faker } from '@faker-js/faker'

export const userFactory = (
  overrides?: Partial<Prisma.UserCreateInput>
): Prisma.UserCreateInput => ({
  name: faker.person.fullName(),
  email: faker.internet.email({ allowSpecialCharacters: false }).toLowerCase(),
  password: faker.internet.password(),
  role: Role.USER,
  emailVerified: true,
  status: UserStatus.ACTIVE,
  ...overrides,
})
