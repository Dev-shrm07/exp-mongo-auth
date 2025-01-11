
import { InferSchemaType, model, Schema } from "mongoose";

const VerifySchema = new Schema({
    email: { type: String, required: true, unique: true },
    createdAt: { type: Date, default: Date.now }, 
    expireAt: { type: Date, default: Date.now, index: { expires: '1h' } } 
});

VerifySchema.pre('save', function (next) {
    this.expireAt = new Date(Date.now() + 60 * 60 * 1000); 
    next();
});

type Verify = InferSchemaType<typeof VerifySchema>;

export default model<Verify>("Verify", VerifySchema);
