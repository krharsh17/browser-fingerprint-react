import { useState } from "react"
import { httpPost } from "./lib/request"

function App() {
  const [userData, setUserData] = useState({
    username: null,
    password: null
  })
  const handleSubmit = async (e) => {
    e.preventDefault()
    const res = await httpPost('/users/add', userData)
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
    <main>
      <h1>Authentication</h1>
      <form onSubmit={handleSubmit}>
        <input type="text" name="username" placeholder="username" onChange={handleChange} autoComplete="username" value={userData.username || ''} />
        <input type="password" name="password" placeholder="password" onChange={handleChange} autoComplete="current-password" value={userData.password || ''} />
        <button type="submit">Sign Up</button>
      </form>
    </main>
  )
}

export default App
