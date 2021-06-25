import { getCustomRepository } from "typeorm";
import { UsersRepositories } from "../repositories/UsersRepositories";

interface IUserRequest {
  name: string;
  email: string;
  admin?: boolean
}

class CreateUserService {
  async execute({ name, email, admin }: IUserRequest) {
    const UserRepository = getCustomRepository(UsersRepositories);

    if (!email) {
      throw new Error("Email incorrect");
    };

    const userAlreadyExists = await UserRepository.findOne({
      email,
    });

    if (userAlreadyExists) {
      throw new Error("User already exists");
    };

    const user = UserRepository.create({
      name,
      email,
      admin
    });

    await UserRepository.save(user);

    return user;
  }
}

export { CreateUserService }