/* eslint-disable react/prop-types */
import { createContext, useState } from "react";
import { useVisitorData } from '@fingerprintjs/fingerprintjs-pro-react'

export const AuthContext = createContext();

const AuthProvider = ({ children }) => {
    const [userData, setUserData] = useState({
        username: null,
        password: null
    })

    const [authenticated, setAuthenticated] = useState(false)

    const signIn = (userData) => {
        setUserData(prev => userData)
        setAuthenticated(prev => true)
    }

    const signOut = () => {
        setUserData(prev => ({
            username: null,
            password: null
        }))
        setAuthenticated(prev => false)
    }

    const visitorData = useVisitorData({
        extendedResult: true
    }, {
        immediate: true
    })

    return (
        <AuthContext.Provider value={{ userData, setUserData, authenticated, signIn, signOut, visitorData }}>
            {children}
        </AuthContext.Provider>
    );

};

export default AuthProvider;