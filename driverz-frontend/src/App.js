
import React from 'react';
import { BrowserRouter as Router, Route, Routes, Link } from 'react-router-dom';
import './App.css'; // Ensure this file exists for additional styling

// Import the Login component (create this component in your project)
import Login from './Login'; // Make sure to create this file

function App() {
  const handleGetStarted = () => {
    console.log('Get Started button clicked!');
  };

  return (
    <Router>
      <div className="App" style={styles.appContainer}>
        <header className="App-header" style={styles.header}>
          <h1 style={styles.title}>Welcome to Driverz!</h1>
          <p style={styles.description}>
            Your rideshare experience starts here. Manage your profile and rides seamlessly.
          </p>
          <Link to="/login"> {/* Use Link for navigation */}
            <button 
              className="get-started-button" 
              onClick={handleGetStarted}
              style={styles.button}
            >
              Get Started
            </button>
          </Link>
        </header>

        {/* Define routes */}
        <Routes>
          <Route path="/login" element={<Login />} />
          {/* Add more routes as needed */}
        </Routes>
      </div>
    </Router>
  );
}

// Styles
const styles = {
  appContainer: {
    backgroundColor: '#002147', // Dark Navy
    color: '#FFFFFF', // Crisp White
    minHeight: '100vh',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
  },
  header: {
    textAlign: 'center',
  },
  title: {
    fontSize: '3rem',
    color: '#FFD700', // Soft Gold
  },
  description: {
    fontSize: '1.5rem',
    margin: '20px 0',
  },
  button: {
    backgroundColor: '#FFD700', // Soft Gold
    color: '#002147', // Dark Navy
    border: 'none',
    borderRadius: '5px',
    padding: '10px 20px',
    fontSize: '1.2rem',
    cursor: 'pointer',
    transition: 'background-color 0.3s', // Smooth transition
  },
};

export default App;
