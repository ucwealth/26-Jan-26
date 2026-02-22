# db/migrate/20260222095314_create_products.rb

class CreateProducts < ActiveRecord::Migration[8.1]
  def change
    create_table :products do |t|
      t.string :name

      t.timestamps
    end
  end
end
