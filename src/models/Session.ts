import mongoose from 'mongoose';
import SessionSchema from '../schemas/SessionSchema';

const Session = mongoose.model('Session', SessionSchema);

export default Session;