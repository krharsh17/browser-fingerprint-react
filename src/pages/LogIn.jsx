import { useNavigate } from 'react-router-dom'
import { httpPost } from "../lib/request"
import { useContext, useEffect } from 'react'
import { AuthContext } from '../auth/AuthContext'

const Login = () => {
    const navigate = useNavigate()
    const { userData, setUserData, signIn, authenticated, VisitorData } = useContext(AuthContext)

    useEffect(() => {
        console.log(`authenticated: `, authenticated)
        if (authenticated) {
            navigate('/dashboard', { replace: true })
        }
    }, [])

    const handleSubmit = async (e) => {
        e.preventDefault()
        const { data, error, isLoading } = VisitorData
        console.log(data, error, isLoading)
        const res = await httpPost('/users/auth', {
            fpjsVisitor: data,
            ...userData
        })
        if (res.success) {
            signIn()
            navigate('/dashboard', { replace: true })
        }
        console.log(res)
    }

    const handleChange = (e) => {
        setUserData(prev => {
            return {
                ...prev,
                [e.target.name]: e.target.value
            }
        })
    }
    return (
        <form onSubmit={handleSubmit}>
            <input type="text" name="username" placeholder="username" onChange={handleChange} autoComplete="username" value={userData.username || ''} />
            <input type="password" name="password" placeholder="password" onChange={handleChange} autoComplete="current-password" value={userData.password || ''} />
            <button type="submit">Log In</button>
        </form>
    )
}

export default Login