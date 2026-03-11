import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import './App.css';
import Dashboard from './components/Dashboard';
import NetworkDetail from './components/NetworkDetail';
import SecurityPanel from './components/SecurityPanel';

function App() {
  return (
    <Router>
      <div className="App">
        <header className="App-header">
          <h1>Campus Network Monitor</h1>
          <nav>
            <Link to="/">Dashboard</Link>
            <Link to="/security">Security</Link>
          </nav>
        </header>

        <main className="App-main">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/network/:networkId" element={<NetworkDetail />} />
            <Route path="/security" element={<SecurityPanel />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
