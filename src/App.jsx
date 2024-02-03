import { Link } from "react-router-dom";

function App() {
  return (
    <main>
      <h1>Authentication</h1>
      <section className="links">
        <Link to={'/signup'}>Sign Up</Link>
        <Link to={'/login'}>Log In</Link>      
      </section>
    </main>
  )
}

export default App
