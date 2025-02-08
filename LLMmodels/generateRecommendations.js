import { GoogleGenerativeAI } from '@google/generative-ai';
// import Queue from 'better-queue';
// import NodeCache from 'node-cache';
import dotenv from 'dotenv';

dotenv.config();

if (!process.env.GOOGLE_AI_API_KEY) {
    throw new Error('GOOGLE_AI_API_KEY is not defined in environment variables');
  }

// Initialize the Google Generative AI client
const genAI = new GoogleGenerativeAI(process.env.GOOGLE_AI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-2.0-flash" });

export const initializeModel = () => {
    return model;
}


// Queue for handling AI requests

// const aiQueue = new Queue(async (task, cb) => {
//   try {
//     const result = await withRetry(() => generateAIResponse(task.prompt));
//     cb(null, result);
//   } catch (error) {
//     cb(error);
//   }
// }, {
//   concurrent: 1,
//   maxRetries: 3,
//   retryDelay: 2000
// });


// Cache for storing AI responses
// const aiCache = new NodeCache({ stdTTL: 3600 });

// export const queueAIRequest = (prompt) => {
//   return new Promise((resolve, reject) => {
//     aiQueue.push({ prompt }, (error, result) => {
//       if (error) reject(error);
//       else resolve(result);
//     });
//   });
// };

// Function to get cached or generate response
const getCachedOrGenerateResponse = async (prompt) => {
    // const cacheKey = Buffer.from(prompt).toString('base64');
    // const cached = aiCache.get(cacheKey);
    
    // if (cached) {
    //   return cached;
    // }
  
    const response = await model.generateContent(prompt);
    let result = response.response.text();
    result = JSON.parse(result.replace("```json", "").replace("```", "").trim());
    return result;

  };



export const generatePrompt = (vulnerabilities) => {
    return `
    Analyze each of the following vulnerabilities and provide recommendations for remediation of each vulnerability:
    ${JSON.stringify(vulnerabilities)}
    Give the recommendations in a structured format as shown below:
        {
        reason: "reason for the recommendation",
        action: "Implement regular security scanning and patching schedule"
        details: ["Regular vulnerability scanning", "Automated patch management", "Security monitoring"]
        priority: "Medium"
        service: "service"
        }
    Give the recommendations in concise and actionable steps.Output should be in JSON format and remove triple backticks from the output along with the json keyword. Make it a valid json object. Also dont include any other text.
    `
}

export const analyzeNetwork = async(vulnerability) => {
    try {
        const prompt = generatePrompt(vulnerability);
        const result = await getCachedOrGenerateResponse(prompt);
        return {

            success:true,
            data:result
        };

    } catch (error) {
        return {
            success:false,
            message:error.message
        };
    }
}


export default model; 


