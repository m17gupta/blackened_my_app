import mongoose, { Schema, Document } from 'mongoose';
import bcrypt from 'bcryptjs';

export interface IUser extends Document {
    name: string;
    email: string;
    password?: string;
    dob?: string;
    role: string;
    createdAt: Date;
    updatedAt: Date;
    comparePassword: (password: string) => Promise<boolean>;
}

const UserSchema: Schema = new Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    dob: { type: String },
    role: { type: String, default: 'user' },
}, {
    timestamps: true,
});

// Hash password before saving
UserSchema.pre('save', async function () {
    const user = this as any;
    if (!user.isModified('password')) return;

    try {
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(user.password, salt);
    } catch (error: any) {
        throw error;
    }
});

// Compare password method
UserSchema.methods.comparePassword = async function (password: string): Promise<boolean> {
    return await bcrypt.compare(password, this.password);
};

export default mongoose.model<IUser>('User', UserSchema);
