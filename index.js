
import express from 'express'
import { PORT, REFRESH_JWT_KEY, SECRET_JWT_KEY } from './config.js'
import { UserRepository } from './user-repository.js'
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser'

// Crear una aplicación Express
const app = express()
// Middleware para parsear JSON en las solicitudes entrantes
app.use(express.json())
// Middleware para parsear las cookies en las solicitudes entrantes
app.use(cookieParser())

// Middleware para verificar el token de acceso y almacenar la sesión del usuario
// app.use((req, res, next) => {
//     // Recuperamos el token de acceso de las cookies
//     const token = req.cookies.access_token
//     // Inicializamos la sesión del usuario en null
//     req.session = { user: null }
//     try {
//         // Verificamos y decodificamos el token utilizando la clave secreta
//         const data = jwt.verify(token, SECRET_JWT_KEY)
//         // Si el token es válido, almacenamos los datos del usuario en la sesión
//         req.session.user = data
//     } catch (error) {
//         // Si el token no es válido o está ausente, simplemente seguimos sin usuario en la sesión
//     }
//     // Continuar con la siguiente ruta o middleware
//     next()
// })


app.use((req, res, next) => {
    let token = req.cookies.access_token
    req.session = { user: null }

    try {
        const data = jwt.verify(token, SECRET_JWT_KEY)
        req.session.user = data
    } catch (error) {
        const refreshToken = req.cookies.refresh_token
        if (refreshToken) {
            try {
                const data = jwt.verify(refreshToken, REFRESH_JWT_KEY)
                const newToken = jwt.sign(
                    { id: data.id, username: data.username },
                    SECRET_JWT_KEY,
                    { expiresIn: '1h' }
                )
                res.cookie('access_token', newToken, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: 'strict',
                    maxAge: 1000 * 60 * 60
                })
                req.session.user = data
            } catch (refreshError) {
                // Handle invalid refresh token, clear cookies if needed
                res.clearCookie('access_token')
                res.clearCookie('refresh_token')
            }
        }
    }
    next()
})


// Configuración del motor de plantillas EJS
app.set('view engine', 'ejs')

// Ruta principal ('/') que renderiza la plantilla 'index'
app.get('/', (req, res) => {
    const { user } = req.session // Recuperamos el usuario de la sesión
    res.render('index', user) // Renderizamos la vista 'index' y pasamos los datos del usuario
})


// Ruta POST para el inicio de sesión
app.post('/login', async (req, res) => {
    const { username, password } = req.body // Recuperamos el username y password del cuerpo de la solicitud

    try {
        // Intentamos iniciar sesión con las credenciales proporcionadas
        const user = await UserRepository.login({ username, password })

        // Si el inicio de sesión es exitoso, generamos un token de acceso (JWT)
        const token = jwt.sign(
            { id: user._id, username: user.username }, // Datos que queremos almacenar en el token
            SECRET_JWT_KEY, // Clave secreta para firmar el token
            { expiresIn: '1m' } // El token expira en 1 hora
        )

        const refreshToken = jwt.sign(
            { id: user._id, username: user.username },
            REFRESH_JWT_KEY,
            { expiresIn: '7d' } // El token expira en 7 dias
        )


        // Enviamos la cookie con el token de acceso y respondemos con los datos del usuario
        res
            .cookie('access_token', token, {
                httpOnly: true, // La cookie solo se puede acceder desde el servidor, no desde el navegador
                secure: process.env.NODE_ENV === 'production', // La cookie solo está disponible en HTTPS si estamos en producción
                sameSite: 'strict', // La cookie solo se envía en solicitudes del mismo dominio
                // maxAge: 1000 * 60 * 60 // La cookie expira en 1 hora
                maxAge: 1000 * 60 // La cookie expira en 1 minuto

            })
            .cookie('refresh_token', refreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 1000 * 60 * 60 * 24 * 7
            })
            .send({ user, token }) // Respondemos con los datos del usuario y el token
    } catch (error) {
        // Si ocurre un error (por ejemplo, credenciales inválidas), respondemos con un error 500
        res.status(500).send(error.message)
    }
})

// Ruta POST para registrar un nuevo usuario
app.post('/register', async (req, res) => {
    const { username, password } = req.body // Recuperamos el username y password del cuerpo de la solicitud

    try {
        // Intentamos crear un nuevo usuario en la base de datos
        const id = await UserRepository.create({ username, password })
        res.send({ id }) // Respondemos con el ID del nuevo usuario creado
    } catch (error) {
        // Si ocurre un error durante la creación del usuario, respondemos con un error 400
        res.status(400).send(error.message)
    }
})

// Ruta POST para cerrar sesión
app.post('/logout', (req, res) => {
    // Limpiamos la cookie del token de acceso para cerrar la sesión
    res
        .clearCookie('access_token') // Eliminamos la cookie de la respuesta
        .clearCookie('refresh_token') // Eliminamos la cookie de la respuesta
        .json({ message: 'Sesión cerrada' }) // Respondemos con un mensaje de confirmación
})

// Ruta GET para acceder a contenido protegido
app.get('/protected', (req, res) => {
    const { user } = req.session // Recuperamos el usuario de la sesión
    // Verificamos si el usuario está autenticado
    if (!user) return res.status(403).send('Acceso no autorizado') // Si no, respondemos con un error 403 (Forbidden)
    // Si el usuario está autenticado, renderizamos la vista 'protected' y pasamos los datos del usuario
    res.render('protected', user)
})

// Iniciamos el servidor en el puerto especificado
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`)
})