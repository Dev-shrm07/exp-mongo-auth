import { InferSchemaType,model,Schema } from "mongoose";

const UserSchema = new Schema({
    username:{type:String,require:true,unique:true},
    email:{type:String,require:true,unique:true},
    profileImg: {type:String,require:true},
    password:{type:String,require:true},
    is_verified:{type:Boolean, require:true,default:false},
    aff:{type:String,require:true}
})

type User = InferSchemaType<typeof UserSchema>

export default model<User>("User",UserSchema)