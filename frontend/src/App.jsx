import { BrowserRouter, Routes, Route } from 'react-router-dom'
import LandingPage from './pages/Landing'
import AnalysisPage from './pages/Analysis'
import ReportPage from './pages/Report'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/analysis/:jobId" element={<AnalysisPage />} />
        <Route path="/report/:jobId" element={<ReportPage />} />
      </Routes>
    </BrowserRouter>
  )
}
