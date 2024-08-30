import crypto from 'node:crypto'

import DBLocal from "db-local";
const { Schema } = new DBLocal({ path: './db' })

import bcrypt from 'bcrypt'
import { SALT_ROUNDS } from './config.js';

const User = Schema('User', {
    _id: { type: String, required: true },
    username: { type: String, required: true },
    password: { type: String, required: true }
})

export class UserRepository {

    static async create({ username, password }) {
        // 1. Validaciones del username y del password
        // if (typeof username !== 'string') throw new Error('el nombre de usuario debe ser una cadena')
        // if (username.length < 3) throw new Error('el nombre de usuario debe tener al menos 3 caracteres')

        // if (typeof password !== 'string') throw new Error('la constraseña debe ser una cadena')
        // if (password.length < 6) throw new Error('la contraseña debe tener al menos 6 caracteres')
        Validation.username(username)
        Validation.password(password)

        // 2. Asegurarse que el username no exista
        const user = User.findOne({ username })
        if (user) throw new Error('Este usuario ya ha sido creado')

        const id = crypto.randomUUID()

        // Encriptar contraseña
        // const hashedPassword = bcrypt.hashSync(password, SALT_ROUNDS)
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS)

        User.create({
            _id: id,
            username,
            password: hashedPassword
        }).save()

        return id
    }

    static login({ username, password }) {
        Validation.username(username)
        Validation.password(password)

        const user = User.findOne({ username })
        if (!user) throw new Error('Usuario no existe')

        const isValid = bcrypt.compareSync(password, user.password)
        if (!isValid) throw new Error('Contraseña invalida')

        // NOTA: NO ENVIAR EL PASSWORD EN LA RESPUESTA!
        // ES MEJOR ENVIAR OBJETO POR OBJETO PARA QUE CUANDO PUEDAS CONTROLAR LOS DATOS QUE SE ENVIAN!
        // ESTE EJEMPLO, SOLO EVITAMOS EL ENVIO DE LA CONSTRASEÑA PERO LOS DEMAS DATOS NO! -- TENER EN CUENTA 
        const { password: _, ...publicUser } = user
        return publicUser
        // return user
    }
}

class Validation {
    static username(username) {
        if (typeof username !== 'string') throw new Error('el nombre de usuario debe ser una cadena')
        if (username.length < 3) throw new Error('el nombre de usuario debe tener al menos 3 caracteres')
    }

    static password(password) {
        if (typeof password !== 'string') throw new Error('la constraseña debe ser una cadena')
        if (password.length < 6) throw new Error('la contraseña debe tener al menos 6 caracteres')
    }
}