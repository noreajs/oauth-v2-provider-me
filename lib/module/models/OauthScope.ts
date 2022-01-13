import { mongooseModel } from "@noreajs/mongoose";
import { Document, Schema } from "mongoose";

export interface IOauthScope extends Document {
  parent: IOauthScope;
  name: string;
  description: string;
  createdAt: Date;
  updatedAt: Date;
}

export default mongooseModel<IOauthScope>({
  name: "OauthScope",
  collection: "oauth_scopes",
  schema: new Schema(
    {
      parent: {
        type: Schema.Types.ObjectId,
        ref: "OauthScope",
        autopopulate: true,
      },
      name: {
        type: Schema.Types.String,
        unique: true,
        required: [true, "The scope name is required."],
      },
      description: {
        type: Schema.Types.String,
        unique: true,
        required: [true, "The scope description is required."],
      },
    },
    {
      timestamps: true,
    }
  ),
});
